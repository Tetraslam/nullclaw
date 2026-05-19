//! Privacy-preserving envelope for LLM-based secret triage.
//!
//! Builds a JSON envelope of metadata about a candidate secret without
//! exposing its raw value to the LLM. The LLM receives shape (length,
//! charset, entropy), context (variable name, file path, surrounding
//! whitelisted keywords) and deterministic flags (is_test_path,
//! is_example_file) — never the literal bytes of the secret.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const SCHEMA_VERSION = "1";

pub const Charset = enum {
    alnum,
    alnum_underscore,
    base64ish,
    base64url,
    hex_lower,
    hex_upper,
    hex_mixed,
    pem_block,
    mixed,

    pub fn name(self: Charset) []const u8 {
        return switch (self) {
            .alnum => "alnum",
            .alnum_underscore => "alnum_underscore",
            .base64ish => "base64ish",
            .base64url => "base64url",
            .hex_lower => "hex_lower",
            .hex_upper => "hex_upper",
            .hex_mixed => "hex_mixed",
            .pem_block => "pem_block",
            .mixed => "mixed",
        };
    }

    pub fn classify(value: []const u8) Charset {
        if (std.mem.indexOf(u8, value, "BEGIN ") != null and std.mem.indexOf(u8, value, "PRIVATE KEY") != null) {
            return .pem_block;
        }

        var has_lower_alpha = false;
        var has_upper_alpha = false;
        var has_digit = false;
        var has_underscore = false;
        var has_dash = false;
        var has_plus = false;
        var has_slash = false;
        var has_equals = false;
        var has_other = false;
        var has_hex_only_lower = true;
        var has_hex_only_upper = true;

        for (value) |ch| {
            if (ch >= 'a' and ch <= 'z') {
                has_lower_alpha = true;
                if (!isHexLower(ch)) has_hex_only_lower = false;
                has_hex_only_upper = false;
            } else if (ch >= 'A' and ch <= 'Z') {
                has_upper_alpha = true;
                if (!isHexUpper(ch)) has_hex_only_upper = false;
                has_hex_only_lower = false;
            } else if (ch >= '0' and ch <= '9') {
                has_digit = true;
            } else if (ch == '_') {
                has_underscore = true;
                has_hex_only_lower = false;
                has_hex_only_upper = false;
            } else if (ch == '-') {
                has_dash = true;
                has_hex_only_lower = false;
                has_hex_only_upper = false;
            } else if (ch == '+') {
                has_plus = true;
                has_hex_only_lower = false;
                has_hex_only_upper = false;
            } else if (ch == '/') {
                has_slash = true;
                has_hex_only_lower = false;
                has_hex_only_upper = false;
            } else if (ch == '=') {
                has_equals = true;
                has_hex_only_lower = false;
                has_hex_only_upper = false;
            } else {
                has_other = true;
                has_hex_only_lower = false;
                has_hex_only_upper = false;
            }
        }

        if (has_other) return .mixed;

        if (has_plus or has_slash or has_equals) return .base64ish;

        if (has_digit and has_lower_alpha and has_upper_alpha and isHexMixed(value)) return .hex_mixed;
        if (has_digit and has_hex_only_lower and !has_upper_alpha) return .hex_lower;
        if (has_digit and has_hex_only_upper and !has_lower_alpha) return .hex_upper;
        if (has_digit and (has_hex_only_lower or has_hex_only_upper) and isHexMixed(value)) return .hex_mixed;

        if (has_dash and has_underscore) return .base64url;
        if (has_dash) return .base64url;
        if (has_underscore) return .alnum_underscore;
        return .alnum;
    }
};

fn isHexLower(ch: u8) bool {
    return (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f');
}

fn isHexUpper(ch: u8) bool {
    return (ch >= '0' and ch <= '9') or (ch >= 'A' and ch <= 'F');
}

fn isHexMixed(value: []const u8) bool {
    for (value) |ch| {
        const lower = (ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f');
        const upper = (ch >= '0' and ch <= '9') or (ch >= 'A' and ch <= 'F');
        if (!lower and !upper) return false;
    }
    return true;
}

pub const TokenTypeFingerprint = enum {
    aws_access_key_id,
    github_pat,
    github_oauth,
    github_app_user,
    github_app_server,
    gitlab_pat,
    slack_bot_token,
    slack_user_token,
    openai_legacy,
    openai_project,
    stripe_live,
    stripe_test,
    pem_private_key,
    high_entropy_random,
    unknown,

    pub fn name(self: TokenTypeFingerprint) []const u8 {
        return switch (self) {
            .aws_access_key_id => "aws_access_key_id",
            .github_pat => "github_pat",
            .github_oauth => "github_oauth",
            .github_app_user => "github_app_user",
            .github_app_server => "github_app_server",
            .gitlab_pat => "gitlab_pat",
            .slack_bot_token => "slack_bot_token",
            .slack_user_token => "slack_user_token",
            .openai_legacy => "openai_legacy",
            .openai_project => "openai_project",
            .stripe_live => "stripe_live",
            .stripe_test => "stripe_test",
            .pem_private_key => "pem_private_key",
            .high_entropy_random => "high_entropy_random",
            .unknown => "unknown",
        };
    }

    pub fn detect(value: []const u8) TokenTypeFingerprint {
        if (std.mem.indexOf(u8, value, "BEGIN ") != null and std.mem.indexOf(u8, value, "PRIVATE KEY") != null) {
            return .pem_private_key;
        }
        if (std.mem.startsWith(u8, value, "AKIA")) return .aws_access_key_id;
        if (std.mem.startsWith(u8, value, "ghp_")) return .github_pat;
        if (std.mem.startsWith(u8, value, "gho_")) return .github_oauth;
        if (std.mem.startsWith(u8, value, "ghu_")) return .github_app_user;
        if (std.mem.startsWith(u8, value, "ghs_")) return .github_app_server;
        if (std.mem.startsWith(u8, value, "glpat-")) return .gitlab_pat;
        if (std.mem.startsWith(u8, value, "xoxb-")) return .slack_bot_token;
        if (std.mem.startsWith(u8, value, "xoxp-")) return .slack_user_token;
        if (std.mem.startsWith(u8, value, "sk-proj-")) return .openai_project;
        if (std.mem.startsWith(u8, value, "sk_live_")) return .stripe_live;
        if (std.mem.startsWith(u8, value, "sk_test_")) return .stripe_test;
        if (std.mem.startsWith(u8, value, "sk-")) return .openai_legacy;

        if (value.len >= 16 and computeShannonEntropy(value) >= 4.0) return .high_entropy_random;
        return .unknown;
    }
};

pub fn computeShannonEntropy(text: []const u8) f64 {
    if (text.len == 0) return 0.0;
    var counts = [_]usize{0} ** 256;
    for (text) |ch| counts[ch] += 1;
    const len_f: f64 = @floatFromInt(text.len);
    var entropy: f64 = 0.0;
    for (counts) |count| {
        if (count == 0) continue;
        const count_f: f64 = @floatFromInt(count);
        const p = count_f / len_f;
        entropy -= p * @log2(p);
    }
    return entropy;
}

const test_path_markers = [_][]const u8{
    "/tests/",
    "/test/",
    "/__tests__/",
    "/spec/",
    "/specs/",
    "/fixtures/",
    "/fixture/",
    "/mocks/",
    "/mock/",
    "_test.",
    ".test.",
    "_spec.",
    ".spec.",
};

pub fn isTestPath(path: []const u8) bool {
    for (test_path_markers) |marker| {
        if (std.mem.indexOf(u8, path, marker) != null) return true;
    }
    if (std.mem.startsWith(u8, path, "tests/") or
        std.mem.startsWith(u8, path, "test/") or
        std.mem.startsWith(u8, path, "spec/") or
        std.mem.startsWith(u8, path, "fixtures/")) return true;
    return false;
}

const example_suffixes = [_][]const u8{
    ".example",
    ".sample",
    ".template",
    ".dist",
    ".tmpl",
    ".tpl",
};

pub fn isExampleFile(path: []const u8) bool {
    const basename = std.fs.path.basename(path);
    for (example_suffixes) |suf| {
        if (std.mem.endsWith(u8, basename, suf)) return true;
    }
    if (std.mem.indexOf(u8, basename, ".example.") != null) return true;
    if (std.mem.indexOf(u8, basename, ".sample.") != null) return true;
    if (std.mem.indexOf(u8, basename, ".template.") != null) return true;
    if (std.mem.startsWith(u8, basename, "example.")) return true;
    if (std.mem.startsWith(u8, basename, "sample.")) return true;
    return false;
}

const canonical_keywords = [_][]const u8{
    "aws",         "gcp",         "azure",    "openai",      "anthropic",
    "slack",       "discord",     "telegram", "github",      "gitlab",
    "bitbucket",   "stripe",      "twilio",   "sendgrid",    "sentry",
    "datadog",     "paypal",      "square",   "plaid",       "secret",
    "key",         "token",       "password", "passwd",      "credential",
    "credentials", "api",         "auth",     "bearer",      "oauth",
    "jwt",         "hmac",        "signing",  "signature",   "private",
    "public",      "encryption",  "encrypt",  "decrypt",     "prod",
    "production",  "staging",     "dev",      "development", "test",
    "fixture",     "example",     "sample",   "database",    "redis",
    "postgres",    "mysql",       "mongo",    "elastic",     "config",
    "env",         "environment", "client",   "server",      "internal",
    "external",    "admin",       "user",     "service",     "webhook",
    "session",     "refresh",     "access",
};

pub fn extractNearbyKeywords(allocator: Allocator, line: []const u8) ![][]const u8 {
    var seen: u128 = 0;
    var matches: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer matches.deinit(allocator);

    var i: usize = 0;
    while (i < line.len) {
        while (i < line.len and !std.ascii.isAlphanumeric(line[i])) : (i += 1) {}
        const start = i;
        while (i < line.len and std.ascii.isAlphanumeric(line[i])) : (i += 1) {}
        if (i == start) continue;
        const token = line[start..i];

        for (canonical_keywords, 0..) |keyword, idx| {
            if (idx >= 128) break;
            const bit = @as(u128, 1) << @intCast(idx);
            if ((seen & bit) != 0) continue;
            if (eqlIgnoreCase(token, keyword)) {
                seen |= bit;
                try matches.append(allocator, keyword);
                break;
            }
        }
    }

    return matches.toOwnedSlice(allocator);
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ax, bx| {
        const al = std.ascii.toLower(ax);
        const bl = std.ascii.toLower(bx);
        if (al != bl) return false;
    }
    return true;
}

pub const BuildInput = struct {
    file_path: []const u8,
    line_no: usize,
    full_line: []const u8,
    value: []const u8,
    variable_name: ?[]const u8,
    detector: []const u8,
    assignment_operator: ?[]const u8 = null,
    is_in_comment: bool = false,
    is_in_docstring: bool = false,
};

pub const Envelope = struct {
    schema_version: []const u8,
    variable_name: ?[]u8,
    file_path: []u8,
    extension: []u8,
    line_context_masked: []u8,
    detector: []u8,
    token_type_fingerprint: []const u8,
    length: usize,
    charset: []const u8,
    entropy: f64,
    nearby_keywords: [][]const u8,
    assignment_operator: ?[]u8,
    is_test_path: bool,
    is_example_file: bool,
    is_in_comment: bool,
    is_in_docstring: bool,
    envelope_hash: [64]u8,

    pub fn deinit(self: *Envelope, allocator: Allocator) void {
        if (self.variable_name) |v| allocator.free(v);
        allocator.free(self.file_path);
        allocator.free(self.extension);
        allocator.free(self.line_context_masked);
        allocator.free(self.detector);
        allocator.free(self.nearby_keywords);
        if (self.assignment_operator) |op| allocator.free(op);
    }
};

pub fn build(allocator: Allocator, input: BuildInput) !Envelope {
    const charset = Charset.classify(input.value);
    const fingerprint = TokenTypeFingerprint.detect(input.value);
    const entropy = computeShannonEntropy(input.value);

    const masked_line = try maskValue(allocator, input.full_line, input.value, charset.name(), entropy);
    errdefer allocator.free(masked_line);

    const nearby = try extractNearbyKeywords(allocator, input.full_line);
    errdefer allocator.free(nearby);

    const ext_basename = std.fs.path.basename(input.file_path);
    const ext_idx = std.mem.lastIndexOfScalar(u8, ext_basename, '.');
    const ext_slice: []const u8 = if (ext_idx) |idx| ext_basename[idx..] else "";

    const file_path = try allocator.dupe(u8, input.file_path);
    errdefer allocator.free(file_path);
    const extension = try allocator.dupe(u8, ext_slice);
    errdefer allocator.free(extension);
    const detector = try allocator.dupe(u8, input.detector);
    errdefer allocator.free(detector);

    const variable_name: ?[]u8 = if (input.variable_name) |v| try allocator.dupe(u8, v) else null;
    errdefer if (variable_name) |v| allocator.free(v);

    const assignment_op: ?[]u8 = if (input.assignment_operator) |op| try allocator.dupe(u8, op) else null;
    errdefer if (assignment_op) |op| allocator.free(op);

    var env: Envelope = .{
        .schema_version = SCHEMA_VERSION,
        .variable_name = variable_name,
        .file_path = file_path,
        .extension = extension,
        .line_context_masked = masked_line,
        .detector = detector,
        .token_type_fingerprint = fingerprint.name(),
        .length = input.value.len,
        .charset = charset.name(),
        .entropy = entropy,
        .nearby_keywords = nearby,
        .assignment_operator = assignment_op,
        .is_test_path = isTestPath(input.file_path),
        .is_example_file = isExampleFile(input.file_path),
        .is_in_comment = input.is_in_comment,
        .is_in_docstring = input.is_in_docstring,
        .envelope_hash = undefined,
    };

    env.envelope_hash = computeEnvelopeHash(env);
    return env;
}

fn maskValue(allocator: Allocator, full_line: []const u8, value: []const u8, charset_name: []const u8, entropy: f64) ![]u8 {
    const placeholder = try std.fmt.allocPrint(allocator, "<SECRET:len={d},charset={s},entropy={d:.1}>", .{ value.len, charset_name, entropy });
    defer allocator.free(placeholder);

    if (value.len == 0) return try allocator.dupe(u8, placeholder);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    var start: usize = 0;
    var masked = false;
    while (std.mem.indexOfPos(u8, full_line, start, value)) |idx| {
        try buf.appendSlice(allocator, full_line[start..idx]);
        try buf.appendSlice(allocator, placeholder);
        start = idx + value.len;
        masked = true;
    }
    if (!masked) return try allocator.dupe(u8, placeholder);
    try buf.appendSlice(allocator, full_line[start..]);
    return try buf.toOwnedSlice(allocator);
}

fn appendFmt(buf: *std.ArrayListUnmanaged(u8), allocator: Allocator, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(rendered);
    try buf.appendSlice(allocator, rendered);
}

fn computeEnvelopeHash(env: Envelope) [64]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(env.schema_version);
    hasher.update("|");
    if (env.variable_name) |v| hasher.update(v);
    hasher.update("|");
    hasher.update(env.file_path);
    hasher.update("|");
    hasher.update(env.detector);
    hasher.update("|");
    hasher.update(env.token_type_fingerprint);
    hasher.update("|");
    var len_buf: [16]u8 = undefined;
    const len_str = std.fmt.bufPrint(&len_buf, "{d}", .{env.length}) catch "";
    hasher.update(len_str);
    hasher.update("|");
    hasher.update(env.charset);
    hasher.update("|");
    var ent_buf: [32]u8 = undefined;
    const ent_str = std.fmt.bufPrint(&ent_buf, "{d:.4}", .{env.entropy}) catch "";
    hasher.update(ent_str);
    hasher.update("|");
    hasher.update(env.line_context_masked);

    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);

    var hex: [64]u8 = undefined;
    const hex_alphabet = "0123456789abcdef";
    for (digest, 0..) |b, i| {
        hex[i * 2] = hex_alphabet[b >> 4];
        hex[i * 2 + 1] = hex_alphabet[b & 0xf];
    }
    return hex;
}

/// Serialize an envelope to a JSON string. Caller owns the returned slice.
pub fn serializeJson(allocator: Allocator, env: Envelope) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(allocator);

    try buf.append(allocator, '{');
    try appendFmt(&buf, allocator, "\"schema_version\":\"{s}\",", .{env.schema_version});
    if (env.variable_name) |v| {
        try buf.appendSlice(allocator, "\"variable_name\":");
        try appendJsonString(&buf, allocator, v);
        try buf.append(allocator, ',');
    } else {
        try buf.appendSlice(allocator, "\"variable_name\":null,");
    }
    try buf.appendSlice(allocator, "\"file_path\":");
    try appendJsonString(&buf, allocator, env.file_path);
    try buf.appendSlice(allocator, ",\"extension\":");
    try appendJsonString(&buf, allocator, env.extension);
    try buf.appendSlice(allocator, ",\"line_context_masked\":");
    try appendJsonString(&buf, allocator, env.line_context_masked);
    try buf.appendSlice(allocator, ",\"detector\":");
    try appendJsonString(&buf, allocator, env.detector);
    try appendFmt(&buf, allocator, ",\"token_type_fingerprint\":\"{s}\"", .{env.token_type_fingerprint});
    try appendFmt(&buf, allocator, ",\"length\":{d}", .{env.length});
    try appendFmt(&buf, allocator, ",\"charset\":\"{s}\"", .{env.charset});
    try appendFmt(&buf, allocator, ",\"entropy\":{d:.4}", .{env.entropy});
    try buf.appendSlice(allocator, ",\"nearby_keywords\":[");
    for (env.nearby_keywords, 0..) |kw, i| {
        if (i > 0) try buf.append(allocator, ',');
        try appendJsonString(&buf, allocator, kw);
    }
    try buf.append(allocator, ']');
    if (env.assignment_operator) |op| {
        try buf.appendSlice(allocator, ",\"assignment_operator\":");
        try appendJsonString(&buf, allocator, op);
    } else {
        try buf.appendSlice(allocator, ",\"assignment_operator\":null");
    }
    try appendFmt(&buf, allocator, ",\"is_test_path\":{s}", .{if (env.is_test_path) "true" else "false"});
    try appendFmt(&buf, allocator, ",\"is_example_file\":{s}", .{if (env.is_example_file) "true" else "false"});
    try appendFmt(&buf, allocator, ",\"is_in_comment\":{s}", .{if (env.is_in_comment) "true" else "false"});
    try appendFmt(&buf, allocator, ",\"is_in_docstring\":{s}", .{if (env.is_in_docstring) "true" else "false"});
    try buf.appendSlice(allocator, ",\"envelope_hash\":\"");
    try buf.appendSlice(allocator, &env.envelope_hash);
    try buf.appendSlice(allocator, "\"}");

    return buf.toOwnedSlice(allocator);
}

fn appendJsonString(buf: *std.ArrayListUnmanaged(u8), allocator: Allocator, s: []const u8) !void {
    try buf.append(allocator, '"');
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
            try appendFmt(buf, allocator, "\\u{x:0>4}", .{ch});
        } else {
            try buf.append(allocator, ch);
        }
    }
    try buf.append(allocator, '"');
}

// =========================================================================
// Tests
// =========================================================================

test "Charset.classify github_pat" {
    try std.testing.expectEqual(Charset.alnum_underscore, Charset.classify("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"));
}

test "Charset.classify aws access key" {
    try std.testing.expectEqual(Charset.alnum, Charset.classify("AKIAIOSFODNN7EXAMPLE"));
}

test "Charset.classify hex lower" {
    try std.testing.expectEqual(Charset.hex_lower, Charset.classify("deadbeef0123456789abcdef"));
}

test "Charset.classify hex upper" {
    try std.testing.expectEqual(Charset.hex_upper, Charset.classify("DEADBEEF0123456789ABCDEF"));
}

test "Charset.classify hex mixed" {
    try std.testing.expectEqual(Charset.hex_mixed, Charset.classify("deadBEEF0123456789ABCDEF"));
}

test "Charset.classify base64ish" {
    try std.testing.expectEqual(Charset.base64ish, Charset.classify("wJalrXUtnFEMI/K7MDENG/bPxRfiCY+EXAMPLEKEY="));
}

test "TokenTypeFingerprint.detect github_pat" {
    try std.testing.expectEqual(TokenTypeFingerprint.github_pat, TokenTypeFingerprint.detect("ghp_aBcDeFgHi"));
}

test "TokenTypeFingerprint.detect openai_project" {
    try std.testing.expectEqual(TokenTypeFingerprint.openai_project, TokenTypeFingerprint.detect("sk-proj-aBc"));
}

test "TokenTypeFingerprint.detect openai_legacy" {
    try std.testing.expectEqual(TokenTypeFingerprint.openai_legacy, TokenTypeFingerprint.detect("sk-aBcDeFg"));
}

test "TokenTypeFingerprint.detect aws_access_key_id" {
    try std.testing.expectEqual(TokenTypeFingerprint.aws_access_key_id, TokenTypeFingerprint.detect("AKIAIOSFODNN7EXAMPLE"));
}

test "TokenTypeFingerprint.detect slack_bot_token" {
    try std.testing.expectEqual(TokenTypeFingerprint.slack_bot_token, TokenTypeFingerprint.detect("xoxb-12345"));
}

test "TokenTypeFingerprint.detect pem private key" {
    try std.testing.expectEqual(TokenTypeFingerprint.pem_private_key, TokenTypeFingerprint.detect("-----BEGIN PRIVATE KEY-----"));
}

test "TokenTypeFingerprint.detect high_entropy_random" {
    try std.testing.expectEqual(TokenTypeFingerprint.high_entropy_random, TokenTypeFingerprint.detect("aBcDeFgHiJkLmNoPqRsTuV"));
}

test "computeShannonEntropy uniform" {
    const e = computeShannonEntropy("abcdefghijklmnop");
    try std.testing.expect(e > 3.9);
}

test "computeShannonEntropy low" {
    const e = computeShannonEntropy("xxxxxxxxxxxxxxxxxx");
    try std.testing.expect(e < 0.5);
}

test "isTestPath" {
    try std.testing.expect(isTestPath("tests/leaky.py"));
    try std.testing.expect(isTestPath("src/module/__tests__/leak.js"));
    try std.testing.expect(isTestPath("foo/fixtures/secrets.env"));
    try std.testing.expect(isTestPath("auth_test.go"));
    try std.testing.expect(!isTestPath("src/main.zig"));
}

test "isExampleFile" {
    try std.testing.expect(isExampleFile(".env.example"));
    try std.testing.expect(isExampleFile("services/.env.template"));
    try std.testing.expect(isExampleFile("config.sample.yaml"));
    try std.testing.expect(!isExampleFile("config.yaml"));
    try std.testing.expect(!isExampleFile("prod.env"));
}

test "extractNearbyKeywords basic" {
    const allocator = std.testing.allocator;
    const kws = try extractNearbyKeywords(allocator, "AWS_SECRET_ACCESS_KEY = \"...\"");
    defer allocator.free(kws);
    try std.testing.expectEqual(@as(usize, 4), kws.len);
}

test "extractNearbyKeywords filters non-canonical" {
    const allocator = std.testing.allocator;
    const kws = try extractNearbyKeywords(allocator, "billing_token = STRIPE_KEY for customer acme-corp");
    defer allocator.free(kws);
    var has_acme = false;
    var has_stripe = false;
    for (kws) |k| {
        if (std.mem.eql(u8, k, "stripe")) has_stripe = true;
        if (std.mem.eql(u8, k, "acme")) has_acme = true;
    }
    try std.testing.expect(has_stripe);
    try std.testing.expect(!has_acme);
}

test "build envelope from github_pat" {
    const allocator = std.testing.allocator;
    var env = try build(allocator, .{
        .file_path = "config/prod.env",
        .line_no = 4,
        .full_line = "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .value = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .variable_name = "GITHUB_TOKEN",
        .detector = "secret_assignment",
        .assignment_operator = "=",
    });
    defer env.deinit(allocator);

    try std.testing.expectEqualStrings("github_pat", env.token_type_fingerprint);
    try std.testing.expectEqual(@as(usize, 40), env.length);
    try std.testing.expect(env.entropy > 3.5);
    try std.testing.expect(!env.is_test_path);
    try std.testing.expect(!env.is_example_file);
    try std.testing.expectEqualStrings(".env", env.extension);
}

test "build envelope masks the value in line context" {
    const allocator = std.testing.allocator;
    var env = try build(allocator, .{
        .file_path = "secrets.env",
        .line_no = 1,
        .full_line = "API_KEY=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .value = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .variable_name = "API_KEY",
        .detector = "env_secret_assignment",
        .assignment_operator = "=",
    });
    defer env.deinit(allocator);

    try std.testing.expect(std.mem.indexOf(u8, env.line_context_masked, "ghp_aBc") == null);
    try std.testing.expect(std.mem.indexOf(u8, env.line_context_masked, "<SECRET:") != null);
    try std.testing.expect(std.mem.indexOf(u8, env.line_context_masked, "API_KEY=") != null);
}

test "build envelope masks repeated values in line context" {
    const allocator = std.testing.allocator;
    const secret = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
    var env = try build(allocator, .{
        .file_path = "secrets.env",
        .line_no = 1,
        .full_line = "TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789 # duplicate ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .value = secret,
        .variable_name = "TOKEN",
        .detector = "env_secret_assignment",
        .assignment_operator = "=",
    });
    defer env.deinit(allocator);

    try std.testing.expect(std.mem.indexOf(u8, env.line_context_masked, secret) == null);
}

test "build envelope flags test path" {
    const allocator = std.testing.allocator;
    var env = try build(allocator, .{
        .file_path = "tests/fixtures/leaky.py",
        .line_no = 5,
        .full_line = "FAKE_TOKEN = \"ghp_test_value_here_xxxxxxxxxxxxxx\"",
        .value = "ghp_test_value_here_xxxxxxxxxxxxxx",
        .variable_name = "FAKE_TOKEN",
        .detector = "secret_assignment",
        .assignment_operator = "=",
    });
    defer env.deinit(allocator);

    try std.testing.expect(env.is_test_path);
}

test "envelope hash is deterministic" {
    const allocator = std.testing.allocator;
    var env_a = try build(allocator, .{
        .file_path = "secrets.env",
        .line_no = 1,
        .full_line = "TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .value = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .variable_name = "TOKEN",
        .detector = "env_secret_assignment",
        .assignment_operator = "=",
    });
    defer env_a.deinit(allocator);

    var env_b = try build(allocator, .{
        .file_path = "secrets.env",
        .line_no = 1,
        .full_line = "TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .value = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .variable_name = "TOKEN",
        .detector = "env_secret_assignment",
        .assignment_operator = "=",
    });
    defer env_b.deinit(allocator);

    try std.testing.expectEqualSlices(u8, &env_a.envelope_hash, &env_b.envelope_hash);
}

test "serializeJson produces valid JSON" {
    const allocator = std.testing.allocator;
    var env = try build(allocator, .{
        .file_path = "secrets.env",
        .line_no = 1,
        .full_line = "API_KEY=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .value = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789",
        .variable_name = "API_KEY",
        .detector = "env_secret_assignment",
        .assignment_operator = "=",
    });
    defer env.deinit(allocator);

    const json = try serializeJson(allocator, env);
    defer allocator.free(json);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
    defer parsed.deinit();

    const obj = parsed.value.object;
    try std.testing.expectEqualStrings("github_pat", obj.get("token_type_fingerprint").?.string);
    try std.testing.expectEqual(@as(i64, 40), obj.get("length").?.integer);
    try std.testing.expect(obj.get("envelope_hash").?.string.len == 64);
    try std.testing.expect(std.mem.indexOf(u8, obj.get("line_context_masked").?.string, "ghp_") == null);
}
