//! Append-only JSONL log of LLM-triage requests for transparency.
//!
//! Every external triage call writes a `sent` line before the LLM request and
//! a `verdict` line after the response. Users can review this file to verify
//! exactly what metadata left their machine, even when a later verdict write fails.

const std = @import("std");
const std_compat = @import("compat");
const Allocator = std.mem.Allocator;
const fs_compat = @import("../fs_compat.zig");
const llm_client = @import("llm_client.zig");
const Verdict = llm_client.Verdict;

pub const AuditLog = struct {
    allocator: Allocator,
    path: []u8,

    pub fn init(allocator: Allocator, path: []const u8) !AuditLog {
        const path_dup = try allocator.dupe(u8, path);
        return .{ .allocator = allocator, .path = path_dup };
    }

    pub fn deinit(self: *AuditLog) void {
        self.allocator.free(self.path);
    }

    pub fn preflight(self: *AuditLog) !void {
        try self.ensureParentDir();
        var file = try fs_compat.openPathForAppend(self.path);
        defer file.close();
    }

    pub fn recordSent(
        self: *AuditLog,
        envelope_json: []const u8,
    ) !void {
        const ts: i64 = std_compat.time.timestamp();
        const line = try std.fmt.allocPrint(
            self.allocator,
            "{{\"timestamp\":{d},\"event\":\"sent\",\"envelope\":{s}}}\n",
            .{ ts, envelope_json },
        );
        defer self.allocator.free(line);
        try self.appendLine(line);
    }

    pub fn recordVerdict(
        self: *AuditLog,
        envelope_hash: []const u8,
        verdict: Verdict,
    ) !void {
        const ts: i64 = std_compat.time.timestamp();
        const hash_escaped = try jsonEscape(self.allocator, envelope_hash);
        defer self.allocator.free(hash_escaped);
        const severity_escaped = try jsonEscape(self.allocator, verdict.severity_adjusted);
        defer self.allocator.free(severity_escaped);
        const reasoning_escaped = try jsonEscape(self.allocator, verdict.reasoning);
        defer self.allocator.free(reasoning_escaped);

        const line = try std.fmt.allocPrint(
            self.allocator,
            "{{\"timestamp\":{d},\"event\":\"verdict\",\"envelope_hash\":\"{s}\",\"verdict\":{{\"decision\":\"{s}\",\"severity_adjusted\":\"{s}\",\"reasoning\":\"{s}\",\"confidence_score\":{d:.4}}}}}\n",
            .{
                ts,
                hash_escaped,
                verdict.decision.name(),
                severity_escaped,
                reasoning_escaped,
                verdict.confidence_score,
            },
        );
        defer self.allocator.free(line);
        try self.appendLine(line);
    }

    fn appendLine(self: *AuditLog, line: []const u8) !void {
        try self.ensureParentDir();
        try fs_compat.appendBytes(self.path, line);
    }

    fn ensureParentDir(self: *AuditLog) !void {
        if (std.fs.path.dirname(self.path)) |dir| {
            try fs_compat.makePath(dir);
        }
    }
};

fn jsonEscape(allocator: Allocator, s: []const u8) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);
    for (s) |ch| {
        if (ch == '"') {
            try buf.appendSlice(allocator, "\\\"");
        } else if (ch == '\\') {
            try buf.appendSlice(allocator, "\\\\");
        } else if (ch == '\n') {
            try buf.appendSlice(allocator, "\\n");
        } else if (ch == '\r') {
            try buf.appendSlice(allocator, "\\r");
        } else if (ch == '\t') {
            try buf.appendSlice(allocator, "\\t");
        } else if (ch < 0x20) {
            const rendered = try std.fmt.allocPrint(allocator, "\\u{x:0>4}", .{ch});
            defer allocator.free(rendered);
            try buf.appendSlice(allocator, rendered);
        } else {
            try buf.append(allocator, ch);
        }
    }
    return buf.toOwnedSlice(allocator);
}

test "audit log record escapes model-controlled verdict strings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const tmp_path = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(tmp_path);
    const path = try std_compat.fs.path.join(std.testing.allocator, &.{ tmp_path, "audit.jsonl" });
    defer std.testing.allocator.free(path);

    var log = try AuditLog.init(std.testing.allocator, path);
    defer log.deinit();

    var verdict = Verdict{
        .decision = .uncertain,
        .severity_adjusted = try std.testing.allocator.dupe(u8, "hi\"gh"),
        .reasoning = try std.testing.allocator.dupe(u8, "line\nbreak\\slash"),
        .confidence_score = 0.5,
    };
    defer verdict.deinit(std.testing.allocator);

    try log.recordSent("{\"envelope_hash\":\"abc123\"}");
    try log.recordVerdict("abc123", verdict);

    const content = try fs_compat.readFileAlloc(tmp.dir, std.testing.allocator, "audit.jsonl", 64 * 1024);
    defer std.testing.allocator.free(content);

    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, content, " \t\r\n"), '\n');
    const sent_line = lines.next() orelse return error.TestUnexpectedResult;
    const verdict_line = lines.next() orelse return error.TestUnexpectedResult;
    try std.testing.expect(lines.next() == null);

    var sent = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, sent_line, .{});
    defer sent.deinit();
    try std.testing.expectEqualStrings("sent", sent.value.object.get("event").?.string);
    try std.testing.expect(sent.value.object.get("envelope").?.object.get("envelope_hash") != null);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, verdict_line, .{});
    defer parsed.deinit();

    try std.testing.expectEqualStrings("verdict", parsed.value.object.get("event").?.string);
    try std.testing.expectEqualStrings("abc123", parsed.value.object.get("envelope_hash").?.string);
    const verdict_obj = parsed.value.object.get("verdict").?.object;
    try std.testing.expectEqualStrings("hi\"gh", verdict_obj.get("severity_adjusted").?.string);
    try std.testing.expectEqualStrings("line\nbreak\\slash", verdict_obj.get("reasoning").?.string);
}
