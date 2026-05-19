//! Shared workspace-audit data types.
//!
//! Keep these structs independent of provider/runtime code so the deterministic
//! scanner can produce reports without depending on LLM transport details.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const Severity = enum {
    medium,
    high,
    critical,

    pub fn toString(self: Severity) []const u8 {
        return switch (self) {
            .medium => "medium",
            .high => "high",
            .critical => "critical",
        };
    }

    pub fn rank(self: Severity) u8 {
        return switch (self) {
            .medium => 1,
            .high => 2,
            .critical => 3,
        };
    }
};

pub const Confidence = enum {
    low,
    medium,
    high,

    pub fn toString(self: Confidence) []const u8 {
        return switch (self) {
            .low => "low",
            .medium => "medium",
            .high => "high",
        };
    }
};

pub const FailureThreshold = enum {
    none,
    medium,
    high,
    critical,

    pub fn toString(self: FailureThreshold) []const u8 {
        return switch (self) {
            .none => "none",
            .medium => "medium",
            .high => "high",
            .critical => "critical",
        };
    }

    pub fn parse(raw: []const u8) ?FailureThreshold {
        const map = std.StaticStringMap(FailureThreshold).initComptime(.{
            .{ "none", .none },
            .{ "medium", .medium },
            .{ "high", .high },
            .{ "critical", .critical },
        });
        return map.get(raw);
    }

    fn rank(self: FailureThreshold) u8 {
        return switch (self) {
            .none => 0,
            .medium => 1,
            .high => 2,
            .critical => 3,
        };
    }
};

pub const FindingSource = enum {
    workspace_file,
    git_staged_diff,
    git_history,

    pub fn toString(self: FindingSource) []const u8 {
        return switch (self) {
            .workspace_file => "workspace_file",
            .git_staged_diff => "git_staged_diff",
            .git_history => "git_history",
        };
    }
};

pub const TriageMode = enum {
    off,
    dry_run,
    external,

    pub fn parse(text: []const u8) ?TriageMode {
        if (std.mem.eql(u8, text, "off")) return .off;
        if (std.mem.eql(u8, text, "dry-run") or std.mem.eql(u8, text, "dry_run")) return .dry_run;
        if (std.mem.eql(u8, text, "external")) return .external;
        return null;
    }
};

test "TriageMode parse accepts documented values only" {
    try std.testing.expectEqual(TriageMode.off, TriageMode.parse("off").?);
    try std.testing.expectEqual(TriageMode.dry_run, TriageMode.parse("dry-run").?);
    try std.testing.expectEqual(TriageMode.dry_run, TriageMode.parse("dry_run").?);
    try std.testing.expectEqual(TriageMode.external, TriageMode.parse("external").?);
    try std.testing.expect(TriageMode.parse("on") == null);
}

pub const Finding = struct {
    severity: Severity,
    confidence: Confidence,
    rule: []u8,
    path: []u8,
    line: ?usize,
    source: FindingSource,
    preview: []u8,
    // Internal fields for LLM triage envelope construction. Not serialized.
    raw_line: ?[]u8 = null,
    detected_value: ?[]u8 = null,
    assignment_key: ?[]u8 = null,
    assignment_operator: ?[]u8 = null,

    pub fn deinit(self: *Finding, allocator: Allocator) void {
        allocator.free(self.rule);
        allocator.free(self.path);
        allocator.free(self.preview);
        if (self.raw_line) |v| allocator.free(v);
        if (self.detected_value) |v| allocator.free(v);
        if (self.assignment_key) |v| allocator.free(v);
        if (self.assignment_operator) |v| allocator.free(v);
    }
};

pub const Report = struct {
    workspace_dir: []const u8,
    repo_root: ?[]u8,
    findings: []Finding,
    medium_count: usize = 0,
    high_count: usize = 0,
    critical_count: usize = 0,
    scanned_source: FindingSource,

    pub fn deinit(self: *Report, allocator: Allocator) void {
        for (self.findings) |*finding| finding.deinit(allocator);
        allocator.free(self.findings);
        if (self.repo_root) |root| allocator.free(root);
    }

    pub fn exceedsThreshold(self: Report, threshold: FailureThreshold) bool {
        if (threshold == .none) return false;
        for (self.findings) |finding| {
            if (finding.severity.rank() >= threshold.rank()) return true;
        }
        return false;
    }
};

pub const TriageStats = struct {
    findings_seen: usize = 0,
    envelopes_built: usize = 0,
    llm_calls: usize = 0,
    verdicts_real: usize = 0,
    verdicts_false: usize = 0,
    verdicts_uncertain: usize = 0,
    findings_dropped: usize = 0,
    findings_adjusted: usize = 0,
    skipped_budget: usize = 0,
    errors: usize = 0,
};
