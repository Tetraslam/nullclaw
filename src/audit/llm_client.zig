//! Envelope-triage call wrapping the project's existing provider abstraction.
//!
//! Reuses src/providers/ — the same code paths the agent uses for any of:
//! anthropic, openai, openrouter, ollama, gemini, vertex, custom OpenAI-
//! compatible. We never speak HTTP directly here; we delegate to
//! the provider vtable/factory and parse the returned text as a Verdict.

const std = @import("std");
const Allocator = std.mem.Allocator;
const providers = @import("../providers/root.zig");

pub const Decision = enum {
    real_secret,
    false_positive,
    uncertain,

    pub fn parse(text: []const u8) Decision {
        if (std.mem.eql(u8, text, "real_secret")) return .real_secret;
        if (std.mem.eql(u8, text, "false_positive")) return .false_positive;
        return .uncertain;
    }

    pub fn name(self: Decision) []const u8 {
        return switch (self) {
            .real_secret => "real_secret",
            .false_positive => "false_positive",
            .uncertain => "uncertain",
        };
    }
};

pub const Verdict = struct {
    decision: Decision,
    severity_adjusted: []u8,
    reasoning: []u8,
    confidence_score: f64,

    pub fn deinit(self: *Verdict, allocator: Allocator) void {
        allocator.free(self.severity_adjusted);
        allocator.free(self.reasoning);
    }
};

pub const TriageProvider = struct {
    name: []const u8,
    model: []const u8,
    api_key: ?[]const u8,
    temperature: f64 = 0.0,
};

const SYSTEM_PROMPT =
    \\You are a security analyst triaging potential secret leaks.
    \\You receive a privacy-preserving JSON envelope describing a candidate
    \\secret found in a code repository. The envelope NEVER contains the raw
    \\secret value — only its shape (length, charset, entropy), its location,
    \\and surrounding context.
    \\
    \\Your job: decide whether this is a real secret leak, a false positive,
    \\or uncertain. Respond with ONLY a JSON object on a single line, no
    \\preamble, no markdown, no code fences.
    \\
    \\Schema:
    \\{"decision":"real_secret"|"false_positive"|"uncertain","severity_adjusted":"critical"|"high"|"medium"|"low","reasoning":"brief explanation under 200 chars","confidence_score":0.0-1.0}
    \\
    \\Rules of thumb:
    \\- token_type_fingerprint is a strong signal: github_pat / aws_access_key_id / slack_bot_token / openai_project / stripe_live etc. → almost always real_secret unless is_test_path or is_example_file is true.
    \\- pem_private_key → critical real_secret unless is_example_file.
    \\- is_test_path=true or is_example_file=true → likely false_positive even with real-looking shape.
    \\- nearby_keywords containing "example", "fake", "placeholder", "sample" → bias toward false_positive.
    \\- Short length (<16) + low entropy (<3.0) + no fingerprint → false_positive (it's a placeholder).
    \\- High entropy (>4.0) + length >=20 + non-test path + no example markers → real_secret.
    \\- is_in_comment=true or is_in_docstring=true → biased toward false_positive (it's an example).
;

/// Submit an envelope to the configured provider and return a parsed verdict.
/// Caller owns the returned Verdict and must call deinit on it.
pub fn triageEnvelope(
    allocator: Allocator,
    provider: TriageProvider,
    envelope_json: []const u8,
) !Verdict {
    var holder = triageProviderHolder(allocator, provider);
    defer holder.deinit();

    const response_text = try holder.provider().chatWithSystem(
        allocator,
        SYSTEM_PROMPT,
        envelope_json,
        provider.model,
        provider.temperature,
    );
    defer allocator.free(response_text);

    const trimmed = std.mem.trim(u8, response_text, " \t\r\n");
    return parseVerdictJson(allocator, stripFences(trimmed));
}

fn triageProviderHolder(allocator: Allocator, provider: TriageProvider) providers.ProviderHolder {
    return providers.ProviderHolder.fromConfig(
        allocator,
        provider.name,
        provider.api_key,
        null,
        true,
        null,
        null,
        false,
        null,
    );
}

fn stripFences(text: []const u8) []const u8 {
    var s = text;
    if (std.mem.startsWith(u8, s, "```json")) {
        s = s[7..];
    } else if (std.mem.startsWith(u8, s, "```")) {
        s = s[3..];
    }
    if (std.mem.endsWith(u8, s, "```")) {
        s = s[0 .. s.len - 3];
    }
    return std.mem.trim(u8, s, " \t\r\n");
}

pub fn parseVerdictJson(allocator: Allocator, text: []const u8) !Verdict {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, text, .{});
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) return error.InvalidVerdict;

    const decision_str = if (root.object.get("decision")) |d|
        (if (d == .string) d.string else "uncertain")
    else
        "uncertain";
    const decision = Decision.parse(decision_str);

    const severity_str = if (root.object.get("severity_adjusted")) |s|
        (if (s == .string) s.string else "medium")
    else
        "medium";
    const severity_dup = try allocator.dupe(u8, severity_str);
    errdefer allocator.free(severity_dup);

    const reasoning_str = if (root.object.get("reasoning")) |r|
        (if (r == .string) r.string else "")
    else
        "";
    const reasoning_dup = try allocator.dupe(u8, reasoning_str);
    errdefer allocator.free(reasoning_dup);

    const confidence: f64 = if (root.object.get("confidence_score")) |c| switch (c) {
        .float => c.float,
        .integer => @floatFromInt(c.integer),
        else => 0.5,
    } else 0.5;

    return .{
        .decision = decision,
        .severity_adjusted = severity_dup,
        .reasoning = reasoning_dup,
        .confidence_score = confidence,
    };
}

test "parseVerdictJson valid" {
    const allocator = std.testing.allocator;
    const text =
        \\{"decision":"real_secret","severity_adjusted":"high","reasoning":"github_pat in non-test config","confidence_score":0.95}
    ;
    var v = try parseVerdictJson(allocator, text);
    defer v.deinit(allocator);
    try std.testing.expectEqual(Decision.real_secret, v.decision);
    try std.testing.expectEqualStrings("high", v.severity_adjusted);
    try std.testing.expect(v.confidence_score > 0.9);
}

test "parseVerdictJson false_positive" {
    const allocator = std.testing.allocator;
    const text =
        \\{"decision":"false_positive","severity_adjusted":"low","reasoning":"placeholder in test fixture","confidence_score":0.9}
    ;
    var v = try parseVerdictJson(allocator, text);
    defer v.deinit(allocator);
    try std.testing.expectEqual(Decision.false_positive, v.decision);
}

test "stripFences removes markdown code fence" {
    const text = "```json\n{\"decision\":\"uncertain\"}\n```";
    const stripped = stripFences(text);
    try std.testing.expect(std.mem.startsWith(u8, stripped, "{"));
    try std.testing.expect(std.mem.endsWith(u8, stripped, "}"));
}

test "triage provider holder supports keyless local provider" {
    var holder = triageProviderHolder(std.testing.allocator, .{
        .name = "ollama",
        .model = "llama3.2",
        .api_key = null,
    });
    defer holder.deinit();

    try std.testing.expectEqualStrings("Ollama", holder.provider().getName());
}
