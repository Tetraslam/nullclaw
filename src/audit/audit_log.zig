//! Append-only JSONL log of LLM-triage requests for transparency.
//!
//! Every triage call writes one line: `{"timestamp":..., "envelope":{...}, "verdict":{...}}`.
//! Users can review this file to verify exactly what metadata left their machine.

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

    pub fn record(
        self: *AuditLog,
        envelope_json: []const u8,
        verdict: Verdict,
    ) !void {
        if (std.fs.path.dirname(self.path)) |dir| {
            fs_compat.makePath(dir) catch {};
        }
        const file = try fs_compat.createPath(self.path, .{ .truncate = false });
        defer file.close();
        try file.seekFromEnd(0);

        const ts: i64 = std_compat.time.timestamp();
        const severity_escaped = try jsonEscape(self.allocator, verdict.severity_adjusted);
        defer self.allocator.free(severity_escaped);
        const reasoning_escaped = try jsonEscape(self.allocator, verdict.reasoning);
        defer self.allocator.free(reasoning_escaped);

        const line = try std.fmt.allocPrint(
            self.allocator,
            "{{\"timestamp\":{d},\"envelope\":{s},\"verdict\":{{\"decision\":\"{s}\",\"severity_adjusted\":\"{s}\",\"reasoning\":\"{s}\",\"confidence_score\":{d:.4}}}}}\n",
            .{
                ts,
                envelope_json,
                verdict.decision.name(),
                severity_escaped,
                reasoning_escaped,
                verdict.confidence_score,
            },
        );
        defer self.allocator.free(line);
        try file.writeAll(line);
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

    try log.record("{}", verdict);

    const content = try fs_compat.readFileAlloc(tmp.dir, std.testing.allocator, "audit.jsonl", 64 * 1024);
    defer std.testing.allocator.free(content);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, std.mem.trim(u8, content, " \t\r\n"), .{});
    defer parsed.deinit();

    const verdict_obj = parsed.value.object.get("verdict").?.object;
    try std.testing.expectEqualStrings("hi\"gh", verdict_obj.get("severity_adjusted").?.string);
    try std.testing.expectEqualStrings("line\nbreak\\slash", verdict_obj.get("reasoning").?.string);
}
