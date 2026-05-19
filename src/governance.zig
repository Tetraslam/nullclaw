//! Data-governance policy helpers.
//!
//! Keep policy decisions here and low-level scanning in `redaction.zig`.
//! This module intentionally stays dependency-light so agent/session/tool
//! boundaries can share the same trust rules without importing each other.

const std = @import("std");
const redaction = @import("redaction.zig");

pub const DisplayTrustScope = enum {
    local_single_user,
    shared_channel,
};

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(a, b);
}

fn sessionKeyHasSegment(session_key: []const u8, segment: []const u8) bool {
    return std.mem.indexOf(u8, session_key, segment) != null;
}

pub fn sessionKeyLooksShared(session_key: []const u8) bool {
    return sessionKeyHasSegment(session_key, ":group:") or
        sessionKeyHasSegment(session_key, ":channel:") or
        sessionKeyHasSegment(session_key, ":thread:");
}

pub fn sessionKeyLooksDirect(session_key: []const u8) bool {
    return sessionKeyHasSegment(session_key, ":direct:");
}

pub fn displayTrustScope(session_key: []const u8, channel: ?[]const u8, is_group: ?bool) DisplayTrustScope {
    if (is_group) |group| {
        if (group) return .shared_channel;
    }
    if (sessionKeyLooksShared(session_key)) return .shared_channel;

    if (channel) |ch| {
        if (eqlIgnoreCase(ch, "cli")) return .local_single_user;
        if (sessionKeyLooksDirect(session_key)) return .local_single_user;
        if (is_group) |group| {
            if (!group) return .local_single_user;
        }
        return .shared_channel;
    }

    return .local_single_user;
}

pub fn shouldRehydrateDisplay(session_key: []const u8, channel: ?[]const u8, is_group: ?bool) bool {
    return displayTrustScope(session_key, channel, is_group) == .local_single_user;
}

pub fn redactForEmbedding(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    var r = redaction.Redactor.init(allocator, .{});
    defer r.deinit();
    return r.redact(allocator, text);
}

test "displayTrustScope treats cli and direct sessions as single-user" {
    try std.testing.expectEqual(
        DisplayTrustScope.local_single_user,
        displayTrustScope("cli:default", "cli", null),
    );
    try std.testing.expectEqual(
        DisplayTrustScope.local_single_user,
        displayTrustScope("slack:main:direct:U123", "slack", null),
    );
    try std.testing.expectEqual(
        DisplayTrustScope.local_single_user,
        displayTrustScope("telegram:main:12345", "telegram", false),
    );
}

test "displayTrustScope treats shared sessions as shared even when channel is present" {
    try std.testing.expectEqual(
        DisplayTrustScope.shared_channel,
        displayTrustScope("telegram:main:group:-1001", "telegram", false),
    );
    try std.testing.expectEqual(
        DisplayTrustScope.shared_channel,
        displayTrustScope("slack:main:channel:C123", "slack", null),
    );
    try std.testing.expectEqual(
        DisplayTrustScope.shared_channel,
        displayTrustScope("telegram:main:12345:thread:9", "telegram", null),
    );
    try std.testing.expectEqual(
        DisplayTrustScope.shared_channel,
        displayTrustScope("telegram:main:12345", "telegram", true),
    );
}

test "redactForEmbedding applies shared embedding-boundary policy" {
    const allocator = std.testing.allocator;
    const safe = try redactForEmbedding(allocator, "reach me at user@example.com with sk-test-secret-token");
    defer allocator.free(safe);

    try std.testing.expect(std.mem.indexOf(u8, safe, "user@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "sk-test-secret-token") == null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, safe, "[TOKEN_1]") != null);
}
