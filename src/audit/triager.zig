//! Orchestrates LLM-based triage of workspace audit findings.
//!
//! For each finding with collected envelope context: build a privacy-safe
//! envelope, optionally call the LLM, write audit-log events, and apply the
//! verdict (drop false positives, adjust severity).

const std = @import("std");
const std_compat = @import("compat");
const Allocator = std.mem.Allocator;

const envelope = @import("envelope.zig");
const llm_client = @import("llm_client.zig");
const audit_log_mod = @import("audit_log.zig");
const types = @import("types.zig");
const fs_compat = @import("../fs_compat.zig");

const Finding = types.Finding;
const Severity = types.Severity;
const Confidence = types.Confidence;
const Report = types.Report;
pub const TriageMode = types.TriageMode;
pub const TriageStats = types.TriageStats;
const Verdict = llm_client.Verdict;
const Decision = llm_client.Decision;

pub const DEFAULT_MAX_LLM_CALLS: usize = 50;

pub const Options = struct {
    mode: TriageMode = .off,
    client: ?llm_client.TriageClient = null,
    max_llm_calls: usize = DEFAULT_MAX_LLM_CALLS,
};

/// Run triage on a report. Mutates `report.findings` (may drop entries).
/// Returns stats; recounts severity totals at the end.
pub fn runTriage(
    allocator: Allocator,
    report: *Report,
    options: Options,
    audit_log_path: []const u8,
) !TriageStats {
    var stats: TriageStats = .{};
    stats.findings_seen = report.findings.len;

    var audit_log = try audit_log_mod.AuditLog.init(allocator, audit_log_path);
    defer audit_log.deinit();
    if (options.mode == .external) {
        try audit_log.preflight();
    }

    var kept: std.ArrayListUnmanaged(Finding) = .empty;
    errdefer {
        for (kept.items) |*f| f.deinit(allocator);
        kept.deinit(allocator);
    }

    for (report.findings) |*finding| {
        const env_opt = buildEnvelopeForFinding(allocator, finding) catch |err| {
            stats.errors += 1;
            std.debug.print("triage: envelope build failed: {s}\n", .{@errorName(err)});
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        };

        if (env_opt == null) {
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        }
        var env = env_opt.?;
        defer env.deinit(allocator);
        stats.envelopes_built += 1;

        const env_json = try envelope.serializeJson(allocator, env);
        defer allocator.free(env_json);

        if (options.mode == .dry_run) {
            try printDryRunEnvelope(env_json);
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        }

        const client = options.client orelse {
            stats.errors += 1;
            std.debug.print("triage: missing LLM triage client\n", .{});
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        };

        if (stats.llm_calls >= options.max_llm_calls) {
            stats.skipped_budget += 1;
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        }

        try audit_log.recordSent(env_json);

        var verdict = client.triageEnvelope(allocator, env_json) catch |err| {
            stats.errors += 1;
            std.debug.print("triage: llm call failed for {s}:{?d}: {s}\n", .{
                finding.path,
                finding.line,
                @errorName(err),
            });
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        };
        defer verdict.deinit(allocator);
        stats.llm_calls += 1;

        try audit_log.recordVerdict(env.envelope_hash[0..], verdict);

        switch (verdict.decision) {
            .real_secret => stats.verdicts_real += 1,
            .false_positive => stats.verdicts_false += 1,
            .uncertain => stats.verdicts_uncertain += 1,
        }

        if (verdict.decision == .false_positive) {
            stats.findings_dropped += 1;
            finding.deinit(allocator);
            finding.* = makeEmptyFinding();
            continue;
        }

        const adjusted = parseSeverity(verdict.severity_adjusted) orelse finding.severity;
        if (adjusted != finding.severity) {
            stats.findings_adjusted += 1;
            finding.severity = adjusted;
        }
        try kept.append(allocator, finding.*);
        finding.* = makeEmptyFinding();
    }

    allocator.free(report.findings);
    report.findings = try kept.toOwnedSlice(allocator);

    report.medium_count = 0;
    report.high_count = 0;
    report.critical_count = 0;
    for (report.findings) |f| {
        switch (f.severity) {
            .medium => report.medium_count += 1,
            .high => report.high_count += 1,
            .critical => report.critical_count += 1,
        }
    }

    return stats;
}

fn buildEnvelopeForFinding(allocator: Allocator, finding: *Finding) !?envelope.Envelope {
    const raw_line = finding.raw_line orelse return null;
    const value = finding.detected_value orelse raw_line;
    if (value.len == 0) return null;

    const env = try envelope.build(allocator, .{
        .file_path = finding.path,
        .line_no = finding.line orelse 0,
        .full_line = raw_line,
        .value = value,
        .variable_name = finding.assignment_key,
        .detector = finding.rule,
        .assignment_operator = finding.assignment_operator,
    });
    return env;
}

fn parseSeverity(text: []const u8) ?Severity {
    if (std.mem.eql(u8, text, "critical")) return .critical;
    if (std.mem.eql(u8, text, "high")) return .high;
    if (std.mem.eql(u8, text, "medium")) return .medium;
    return null;
}

fn makeEmptyFinding() Finding {
    return .{
        .severity = .medium,
        .confidence = .low,
        .rule = &[_]u8{},
        .path = &[_]u8{},
        .line = null,
        .source = .workspace_file,
        .preview = &[_]u8{},
    };
}

fn printDryRunEnvelope(env_json: []const u8) !void {
    std.debug.print("[dry-run-llm] {s}\n", .{env_json});
}

test "runTriage respects max llm calls" {
    const allocator = std.testing.allocator;

    const TestClient = struct {
        calls: usize = 0,

        fn triageEnvelope(ptr: *anyopaque, a: Allocator, _: []const u8) !Verdict {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            self.calls += 1;
            return .{
                .decision = .real_secret,
                .severity_adjusted = try a.dupe(u8, "high"),
                .reasoning = try a.dupe(u8, "real token shape"),
                .confidence_score = 0.9,
            };
        }

        const vtable = llm_client.TriageClient.VTable{
            .triageEnvelope = triageEnvelope,
        };
    };

    var findings = try allocator.alloc(Finding, 2);
    findings[0] = try testFinding(allocator, ".env", "API_KEY=sk-live-1234567890abcdef");
    findings[1] = try testFinding(allocator, "config.txt", "TOKEN=ghp_abcd1234567890secret");
    var report = Report{
        .workspace_dir = "/tmp/ws",
        .repo_root = null,
        .findings = findings,
        .high_count = 2,
        .scanned_source = .workspace_file,
    };
    defer report.deinit(allocator);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const tmp_path = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(tmp_path);
    const log_path = try std.fs.path.join(allocator, &.{ tmp_path, "audit.jsonl" });
    defer allocator.free(log_path);

    var test_client = TestClient{};
    const stats = try runTriage(allocator, &report, .{
        .mode = .external,
        .client = .{ .ptr = &test_client, .vtable = &TestClient.vtable },
        .max_llm_calls = 1,
    }, log_path);

    try std.testing.expectEqual(@as(usize, 1), test_client.calls);
    try std.testing.expectEqual(@as(usize, 1), stats.llm_calls);
    try std.testing.expectEqual(@as(usize, 1), stats.skipped_budget);
    try std.testing.expectEqual(@as(usize, 2), report.findings.len);

    const log_content = try fs_compat.readFileAlloc(tmp.dir, allocator, "audit.jsonl", 64 * 1024);
    defer allocator.free(log_content);
    var lines = std.mem.splitScalar(u8, std.mem.trim(u8, log_content, " \t\r\n"), '\n');
    const sent_line = lines.next() orelse return error.TestUnexpectedResult;
    const verdict_line = lines.next() orelse return error.TestUnexpectedResult;
    try std.testing.expect(lines.next() == null);

    var sent = try std.json.parseFromSlice(std.json.Value, allocator, sent_line, .{});
    defer sent.deinit();
    var verdict = try std.json.parseFromSlice(std.json.Value, allocator, verdict_line, .{});
    defer verdict.deinit();
    try std.testing.expectEqualStrings("sent", sent.value.object.get("event").?.string);
    try std.testing.expectEqualStrings("verdict", verdict.value.object.get("event").?.string);
    const sent_hash = sent.value.object.get("envelope").?.object.get("envelope_hash").?.string;
    try std.testing.expectEqualStrings(sent_hash, verdict.value.object.get("envelope_hash").?.string);
}

fn testFinding(allocator: Allocator, path: []const u8, raw_line: []const u8) !Finding {
    return .{
        .severity = .high,
        .confidence = .high,
        .rule = try allocator.dupe(u8, "hardcoded_token"),
        .path = try allocator.dupe(u8, path),
        .line = 1,
        .source = .workspace_file,
        .preview = try allocator.dupe(u8, "preview"),
        .raw_line = try allocator.dupe(u8, raw_line),
        .detected_value = try allocator.dupe(u8, raw_line),
        .assignment_key = null,
        .assignment_operator = null,
    };
}
