//! Anonymize text tool.
//!
//! Thin wrapper around the reusable redaction primitive. Lets the agent
//! anonymize a single piece of free-form text on demand (e.g. before pasting a
//! user-supplied snippet into a notebook, ticket, or downstream tool).
//!
//! Each invocation uses a fresh Redactor, so placeholder ids (`[EMAIL_1]`,
//! `[CARD_2]`, ...) restart from 1 and are deterministic within one call.
//! Cross-call coupling lives intentionally in the agent-wide pre-provider
//! redactor, not here.
//!
//! For enabled categories, matched values are replaced with deterministic
//! placeholders.

const std = @import("std");
const root = @import("root.zig");
const redaction = @import("../redaction.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

/// Hard cap on input size to keep memory bounded on adversarial input.
/// 256 KiB matches the read-only sqlite_query result cap and is plenty for any
/// realistic single-message scrub.
const MAX_INPUT_BYTES: usize = 256 * 1024;

pub const AnonymizeTextTool = struct {
    pub const tool_name = "anonymize_text";
    pub const tool_description =
        "Replace personally-identifiable or sensitive substrings in `text` " ++
        "with deterministic placeholders like [EMAIL_1], [PHONE_1], [CARD_1], " ++
        "[ID_1], [TOKEN_1]. Detects emails, common phone numbers, " ++
        "Luhn-validated card numbers, anchored passport/id values, and " ++
        "common API token / secret patterns. Each call is independent — " ++
        "placeholder counters restart from 1. Use to scrub user-supplied " ++
        "snippets before logging, exporting, or sending downstream. Returns " ++
        "the redacted text as a plain string. Categories can be disabled " ++
        "individually via `redact_*` flags (default: all true).";
    pub const tool_params =
        \\{"type":"object","properties":{"text":{"type":"string","description":"Free-form text to anonymize. Maximum 262144 bytes."},"redact_email":{"type":"boolean","description":"Redact email addresses. Default: true."},"redact_phone":{"type":"boolean","description":"Redact common phone numbers. Default: true."},"redact_card":{"type":"boolean","description":"Redact Luhn-valid card numbers. Default: true."},"redact_id":{"type":"boolean","description":"Redact anchored passport/id values (e.g. `passport: 12345678`). Default: true."},"redact_tokens":{"type":"boolean","description":"Redact API tokens and secrets (Bearer, sk-, ghp_, api_key=, etc.). Default: true."}},"required":["text"]}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *AnonymizeTextTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(_: *AnonymizeTextTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const text = root.getString(args, "text") orelse {
            return failOwned(allocator, "missing required parameter: text");
        };
        if (text.len > MAX_INPUT_BYTES) {
            return failOwnedFmt(
                allocator,
                "text exceeds maximum input size of {d} bytes",
                .{MAX_INPUT_BYTES},
            );
        }

        const cfg = redaction.Config{
            .redact_email = root.getBool(args, "redact_email") orelse true,
            .redact_phone = root.getBool(args, "redact_phone") orelse true,
            .redact_card = root.getBool(args, "redact_card") orelse true,
            .redact_id = root.getBool(args, "redact_id") orelse true,
            .redact_tokens = root.getBool(args, "redact_tokens") orelse true,
        };

        var r = redaction.Redactor.init(allocator, cfg);
        defer r.deinit();

        const redacted = try r.redact(allocator, text);
        return ToolResult{ .success = true, .output = redacted };
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Error helpers
// ════════════════════════════════════════════════════════════════════════════

fn failOwned(allocator: std.mem.Allocator, msg: []const u8) !ToolResult {
    return ToolResult{ .success = false, .output = try allocator.dupe(u8, msg) };
}

fn failOwnedFmt(
    allocator: std.mem.Allocator,
    comptime fmt: []const u8,
    args: anytype,
) !ToolResult {
    return ToolResult{ .success = false, .output = try std.fmt.allocPrint(allocator, fmt, args) };
}

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "anonymize_text: tool exposes name, description, params" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    try std.testing.expectEqualStrings("anonymize_text", t.name());
    try std.testing.expect(t.description().len > 0);
    try std.testing.expect(t.parametersJson().len > 0);
    try std.testing.expect(t.parametersJson()[0] == '{');
}

test "anonymize_text: redacts email" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{\"text\":\"contact me at user@example.com\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("contact me at [EMAIL_1]", result.output);
}

test "anonymize_text: redacts plus-prefixed phone" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{\"text\":\"call +12025551234 now\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("call [PHONE_1] now", result.output);
}

test "anonymize_text: redacts Luhn-valid card" {
    // 4111 1111 1111 1111 is the standard Visa test card (Luhn-valid).
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{\"text\":\"paid with 4111 1111 1111 1111\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("paid with [CARD_1]", result.output);
}

test "anonymize_text: redacts anchored passport id" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{\"text\":\"passport: 4516378901\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("passport: [ID_1]", result.output);
}

test "anonymize_text: redacts Bearer token" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{\"text\":\"auth Bearer eyJhbGciOiJ\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("auth Bearer [TOKEN_1]", result.output);
}

test "anonymize_text: multi-category in single call uses sequential ids" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs(
        "{\"text\":\"user a@b.co paid 4111 1111 1111 1111\"}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("user [EMAIL_1] paid [CARD_1]", result.output);
}

test "anonymize_text: non-sensitive text passes through verbatim" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{\"text\":\"hello world, no secrets here\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("hello world, no secrets here", result.output);
}

test "anonymize_text: redact_email=false leaves email intact" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs(
        "{\"text\":\"contact a@b.co\",\"redact_email\":false}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("contact a@b.co", result.output);
}

test "anonymize_text: redact_tokens=false leaves Bearer header intact" {
    // Regression: granular flags must propagate into the Redactor.Config.
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs(
        "{\"text\":\"auth Bearer eyJhbGciOiJ\",\"redact_tokens\":false}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("auth Bearer eyJhbGciOiJ", result.output);
}

test "anonymize_text: missing text param returns failed result" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "text") != null);
}

test "anonymize_text: empty text yields empty success output" {
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{\"text\":\"\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("", result.output);
}

test "anonymize_text: oversized input rejected without allocating redactor state" {
    // Regression: input larger than MAX_INPUT_BYTES must be rejected before we
    // build any Redactor maps, so the test allocator stays leak-free even on
    // the rejection path.
    const allocator = std.testing.allocator;
    const big = try allocator.alloc(u8, MAX_INPUT_BYTES + 1);
    defer allocator.free(big);
    @memset(big, 'a');

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var obj: JsonObjectMap = .empty;
    try obj.put(arena_alloc, "text", .{ .string = big });

    var at = AnonymizeTextTool{};
    const t = at.tool();
    const result = try t.execute(allocator, obj);
    defer allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "maximum input size") != null);
}

test "anonymize_text: same value within one call reuses placeholder id" {
    // Regression: a single email mentioned twice in the same call must collapse
    // to one stable placeholder so downstream tools can correlate references.
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs(
        "{\"text\":\"a@b.co and a@b.co are the same\"}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqualStrings("[EMAIL_1] and [EMAIL_1] are the same", result.output);
}

test "anonymize_text: independent calls restart placeholder counters" {
    // Regression: the tool intentionally uses a fresh Redactor per call, so the
    // first email of every invocation must be [EMAIL_1].
    var at = AnonymizeTextTool{};
    const t = at.tool();

    {
        const parsed = try root.parseTestArgs("{\"text\":\"first x@y.co\"}");
        defer parsed.deinit();
        const result = try t.execute(std.testing.allocator, parsed.value.object);
        defer std.testing.allocator.free(result.output);
        try std.testing.expect(result.success);
        try std.testing.expectEqualStrings("first [EMAIL_1]", result.output);
    }
    {
        const parsed = try root.parseTestArgs("{\"text\":\"second p@q.io\"}");
        defer parsed.deinit();
        const result = try t.execute(std.testing.allocator, parsed.value.object);
        defer std.testing.allocator.free(result.output);
        try std.testing.expect(result.success);
        try std.testing.expectEqualStrings("second [EMAIL_1]", result.output);
    }
}

test "anonymize_text: never leaks original sensitive substrings on success" {
    // Negative security test: scan the output for verbatim copies of every
    // sensitive substring we fed in. Anything left intact is a leak.
    //
    // Categories are separated by newlines on purpose. The phone matcher
    // tolerates spaces/hyphens/parens between digits and is capped at 15 digits,
    // so a layout like `+1202555... 4111 1111 1111 1111` would let the phone
    // matcher greedily eat the leading digits of the card and suppress the
    // [CARD_1] match. A non-digit, non-allowed-separator like '\n' guarantees
    // each detector sees its category in isolation.
    const sensitive = [_][]const u8{
        "user@example.com",
        "+12025551234",
        "4111 1111 1111 1111",
        "4111111111111111",
        "Bearer eyJhbGciOiJ",
        "sk-abcdef123",
    };
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs(
        "{\"text\":\"user@example.com\\n+12025551234\\n4111 1111 1111 1111\\nauth Bearer eyJhbGciOiJ\\nsk-abcdef123\"}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    for (sensitive) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, result.output, needle) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[PHONE_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[CARD_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[TOKEN_1]") != null);
}

// ════════════════════════════════════════════════════════════════════════════
// Negative security tests
// ════════════════════════════════════════════════════════════════════════════

test "anonymize_text: text param of wrong JSON type rejected without leak" {
    // Regression: a non-string `text` (here: integer) must fail closed via the
    // missing-parameter path; the tool must not panic, leak, or echo the value.
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs("{\"text\":42}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "42") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "text") != null);
}

test "anonymize_text: redact_email with non-bool type falls back to default-on" {
    // Regression: type-confusion via `"redact_email":"false"` (string, not bool)
    // must not silently disable redaction — defaults stay enabled.
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const parsed = try root.parseTestArgs(
        "{\"text\":\"contact a@b.co\",\"redact_email\":\"false\"}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "a@b.co") == null);
    try std.testing.expectEqualStrings("contact [EMAIL_1]", result.output);
}

test "anonymize_text: input exactly at MAX_INPUT_BYTES accepted" {
    // Regression: off-by-one on the size guard would either reject valid input
    // or accept oversized input. Lock both edges of the boundary.
    const allocator = std.testing.allocator;
    const filler = try allocator.alloc(u8, MAX_INPUT_BYTES);
    defer allocator.free(filler);
    @memset(filler, 'a');

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var obj: JsonObjectMap = .empty;
    try obj.put(arena_alloc, "text", .{ .string = filler });

    var at = AnonymizeTextTool{};
    const t = at.tool();
    const result = try t.execute(allocator, obj);
    defer allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expectEqual(@as(usize, MAX_INPUT_BYTES), result.output.len);
}

test "anonymize_text: high-cardinality input redacts every unique value" {
    // Regression: many unique values must each get a placeholder and none of
    // them must survive verbatim in the output.
    var at = AnonymizeTextTool{};
    const t = at.tool();

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(std.testing.allocator);
    try buf.appendSlice(std.testing.allocator, "{\"text\":\"");
    var i: usize = 0;
    while (i < 25) : (i += 1) {
        var line_buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buf, "user{d}@example.com\\n", .{i});
        try buf.appendSlice(std.testing.allocator, line);
    }
    try buf.appendSlice(std.testing.allocator, "\"}");

    const parsed = try root.parseTestArgs(buf.items);
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);

    i = 0;
    while (i < 25) : (i += 1) {
        var needle_buf: [64]u8 = undefined;
        const needle = try std.fmt.bufPrint(&needle_buf, "user{d}@example.com", .{i});
        try std.testing.expect(std.mem.indexOf(u8, result.output, needle) == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[EMAIL_25]") != null);
}

test "anonymize_text: parametersJson advertises every redact_* flag" {
    // Regression: tool schema and execute() config must stay in lockstep so
    // models can actually reach every category-disable flag.
    var at = AnonymizeTextTool{};
    const t = at.tool();
    const params = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, params, "redact_email") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "redact_phone") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "redact_card") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "redact_id") != null);
    try std.testing.expect(std.mem.indexOf(u8, params, "redact_tokens") != null);
}
