//! Orchestrates LLM-based triage of workspace audit findings.
//!
//! For each finding with collected envelope context: build a privacy-safe
//! envelope, optionally call the LLM, log to the audit log, and apply the
//! verdict (drop false positives, adjust severity).

const std = @import("std");
const Allocator = std.mem.Allocator;

const envelope = @import("envelope.zig");
const llm_client = @import("llm_client.zig");
const audit_log_mod = @import("audit_log.zig");
const workspace_audit = @import("../workspace_audit.zig");

const Finding = workspace_audit.Finding;
const Severity = workspace_audit.Severity;
const Confidence = workspace_audit.Confidence;
const Report = workspace_audit.Report;
const Options = workspace_audit.Options;
const Verdict = llm_client.Verdict;
const Decision = llm_client.Decision;

pub const TriageStats = struct {
    findings_seen: usize = 0,
    envelopes_built: usize = 0,
    llm_calls: usize = 0,
    verdicts_real: usize = 0,
    verdicts_false: usize = 0,
    verdicts_uncertain: usize = 0,
    findings_dropped: usize = 0,
    findings_adjusted: usize = 0,
    errors: usize = 0,
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

        if (options.triage_mode == .dry_run) {
            try printDryRunEnvelope(env_json);
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        }

        const provider_name = options.triage_provider orelse {
            stats.errors += 1;
            std.debug.print("triage: missing provider (configure agents.defaults.model.primary)\n", .{});
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        };
        const model_name = options.triage_model orelse {
            stats.errors += 1;
            std.debug.print("triage: missing model (configure agents.defaults.model.primary)\n", .{});
            try kept.append(allocator, finding.*);
            finding.* = makeEmptyFinding();
            continue;
        };
        var verdict = llm_client.triageEnvelope(allocator, .{
            .name = provider_name,
            .model = model_name,
            .api_key = options.triage_api_key,
        }, env_json) catch |err| {
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

        try audit_log.record(env_json, verdict);

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

pub fn renderStatsText(allocator: Allocator, stats: TriageStats) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "Triage: {d} findings | {d} envelopes | {d} llm calls | verdicts: {d} real, {d} false_positive, {d} uncertain | dropped {d}, adjusted {d}, errors {d}\n",
        .{
            stats.findings_seen,
            stats.envelopes_built,
            stats.llm_calls,
            stats.verdicts_real,
            stats.verdicts_false,
            stats.verdicts_uncertain,
            stats.findings_dropped,
            stats.findings_adjusted,
            stats.errors,
        },
    );
}
