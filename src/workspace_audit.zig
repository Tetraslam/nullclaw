const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("fs_compat.zig");
const json_util = @import("json_util.zig");
const admin_output = @import("admin_output.zig");
const scrub = @import("providers/scrub.zig");
const util = @import("util.zig");
const process_util = @import("tools/process_util.zig");

const Allocator = std.mem.Allocator;

const MAX_SCAN_FILE_BYTES: u64 = 256 * 1024;
const MAX_PREVIEW_CHARS: usize = 160;
const MAX_DIFF_BYTES: usize = 512 * 1024;

const skipped_dirs = [_][]const u8{
    ".git",
    ".zig-cache",
    "zig-cache",
    "zig-out",
    "zig-pkg",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
};

const ignored_path_prefixes = [_][]const u8{
    ".git/",
    ".zig-cache/",
    "zig-cache/",
    "zig-out/",
    "zig-pkg/",
    "node_modules/",
    "vendor/",
    "dist/",
    "build/",
    "target/",
    "coverage/",
};

const token_prefixes = [_][]const u8{
    "sk-",
    "xoxb-",
    "xoxp-",
    "ghp_",
    "gho_",
    "ghs_",
    "ghu_",
    "glpat-",
    "AKIA",
};

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

    fn rank(self: Severity) u8 {
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

pub const Options = struct {
    workspace_dir: []const u8,
    json: bool = false,
    staged: bool = false,
    commit: ?[]const u8 = null,
    range: ?[]const u8 = null,
    fail_on: FailureThreshold = .high,
    only_secrets: bool = false,
    exclude_patterns: []const []const u8 = &.{},
};

pub const Finding = struct {
    severity: Severity,
    confidence: Confidence,
    rule: []u8,
    path: []u8,
    line: ?usize,
    source: FindingSource,
    preview: []u8,

    fn deinit(self: *Finding, allocator: Allocator) void {
        allocator.free(self.rule);
        allocator.free(self.path);
        allocator.free(self.preview);
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

pub const AuditError = error{
    NotGitRepository,
    GitUnavailable,
    GitDiffFailed,
    InvalidHistoryTarget,
};

const DetectedRule = struct {
    severity: Severity,
    confidence: Confidence,
    rule: []const u8,
};

const PathCategory = enum {
    config,
    code,
    docs,
    vendor_like,
    neutral,
};

pub fn run(allocator: Allocator, options: Options) !u8 {
    const resolved_workspace = try fs_compat.realpathAllocPath(allocator, options.workspace_dir);
    defer allocator.free(resolved_workspace);

    var report = try buildReport(allocator, resolved_workspace, options);
    defer report.deinit(allocator);

    const rendered = if (options.json)
        try renderJson(allocator, report, options.fail_on)
    else
        try renderText(allocator, report, options.fail_on);
    defer allocator.free(rendered);

    try admin_output.writeStdoutBytes(rendered);
    if (rendered.len == 0 or rendered[rendered.len - 1] != '\n') {
        try admin_output.writeStdoutBytes("\n");
    }

    return if (report.exceedsThreshold(options.fail_on)) 1 else 0;
}

pub fn buildReport(allocator: Allocator, workspace_dir: []const u8, options: Options) !Report {
    const repo_root = try resolveRepoRoot(allocator, workspace_dir);

    var findings: std.ArrayListUnmanaged(Finding) = .empty;
    errdefer {
        for (findings.items) |*finding| finding.deinit(allocator);
        findings.deinit(allocator);
        if (repo_root) |root| allocator.free(root);
    }

    if (options.commit) |commit| {
        const diff = try readCommitDiff(allocator, workspace_dir, commit);
        defer allocator.free(diff);
        try scanGitHistoryDiff(allocator, diff, options, &findings);
    } else if (options.range) |range| {
        const diff = try readRangeDiff(allocator, workspace_dir, range);
        defer allocator.free(diff);
        try scanGitHistoryDiff(allocator, diff, options, &findings);
    } else if (options.staged) {
        const diff = try readStagedDiff(allocator, workspace_dir);
        defer allocator.free(diff);
        try scanStagedDiff(allocator, diff, options, &findings);
    } else {
        try scanWorkspaceFiles(allocator, workspace_dir, workspace_dir, options, &findings);
    }

    var report = Report{
        .workspace_dir = workspace_dir,
        .repo_root = repo_root,
        .findings = try findings.toOwnedSlice(allocator),
        .scanned_source = if (options.commit != null or options.range != null)
            .git_history
        else if (options.staged)
            .git_staged_diff
        else
            .workspace_file,
    };

    for (report.findings) |finding| {
        switch (finding.severity) {
            .medium => report.medium_count += 1,
            .high => report.high_count += 1,
            .critical => report.critical_count += 1,
        }
    }
    return report;
}

fn resolveRepoRoot(allocator: Allocator, cwd: []const u8) !?[]u8 {
    const result = process_util.run(allocator, &.{ "git", "rev-parse", "--show-toplevel" }, .{
        .cwd = cwd,
        .max_output_bytes = 32 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer result.deinit(allocator);

    if (!result.success) {
        if (containsText(result.stderr, "not a git repository") or containsText(result.stderr, "not recognized as an internal or external command")) {
            return null;
        }
        if (containsText(result.stderr, "No such file or directory")) return null;
        if (containsText(result.stderr, "command not found")) return null;
        return null;
    }

    const trimmed = std.mem.trim(u8, result.stdout, " \r\n\t");
    if (trimmed.len == 0) return null;
    return try allocator.dupe(u8, trimmed);
}

fn readStagedDiff(allocator: Allocator, cwd: []const u8) ![]u8 {
    const version = process_util.run(allocator, &.{ "git", "--version" }, .{
        .cwd = cwd,
        .max_output_bytes = 16 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return AuditError.GitUnavailable,
        else => return err,
    };
    defer version.deinit(allocator);
    if (!version.success) return AuditError.GitUnavailable;

    const result = process_util.run(allocator, &.{ "git", "diff", "--cached", "--unified=0", "--no-color", "--", "." }, .{
        .cwd = cwd,
        .max_output_bytes = MAX_DIFF_BYTES,
    }) catch |err| switch (err) {
        error.FileNotFound => return AuditError.GitUnavailable,
        else => return err,
    };
    defer allocator.free(result.stderr);

    if (!result.success) {
        defer allocator.free(result.stdout);
        if (containsText(result.stderr, "not a git repository")) return AuditError.NotGitRepository;
        return AuditError.GitDiffFailed;
    }

    return result.stdout;
}

fn readCommitDiff(allocator: Allocator, cwd: []const u8, commit: []const u8) ![]u8 {
    if (commit.len == 0) return AuditError.InvalidHistoryTarget;
    const version = process_util.run(allocator, &.{ "git", "--version" }, .{
        .cwd = cwd,
        .max_output_bytes = 16 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return AuditError.GitUnavailable,
        else => return err,
    };
    defer version.deinit(allocator);
    if (!version.success) return AuditError.GitUnavailable;

    const result = process_util.run(allocator, &.{ "git", "show", "--format=", "--unified=0", "--no-color", commit, "--", "." }, .{
        .cwd = cwd,
        .max_output_bytes = MAX_DIFF_BYTES,
    }) catch |err| switch (err) {
        error.FileNotFound => return AuditError.GitUnavailable,
        else => return err,
    };
    defer allocator.free(result.stderr);

    if (!result.success) {
        defer allocator.free(result.stdout);
        if (containsText(result.stderr, "not a git repository")) return AuditError.NotGitRepository;
        return AuditError.GitDiffFailed;
    }

    return result.stdout;
}

fn readRangeDiff(allocator: Allocator, cwd: []const u8, range: []const u8) ![]u8 {
    if (range.len == 0 or std.mem.indexOf(u8, range, "..") == null) return AuditError.InvalidHistoryTarget;
    const version = process_util.run(allocator, &.{ "git", "--version" }, .{
        .cwd = cwd,
        .max_output_bytes = 16 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return AuditError.GitUnavailable,
        else => return err,
    };
    defer version.deinit(allocator);
    if (!version.success) return AuditError.GitUnavailable;

    const result = process_util.run(allocator, &.{ "git", "diff", "--unified=0", "--no-color", range, "--", "." }, .{
        .cwd = cwd,
        .max_output_bytes = MAX_DIFF_BYTES,
    }) catch |err| switch (err) {
        error.FileNotFound => return AuditError.GitUnavailable,
        else => return err,
    };
    defer allocator.free(result.stderr);

    if (!result.success) {
        defer allocator.free(result.stdout);
        if (containsText(result.stderr, "not a git repository")) return AuditError.NotGitRepository;
        return AuditError.GitDiffFailed;
    }

    return result.stdout;
}

fn scanWorkspaceFiles(
    allocator: Allocator,
    root_dir: []const u8,
    current_dir: []const u8,
    options: Options,
    findings: *std.ArrayListUnmanaged(Finding),
) !void {
    var dir = try std_compat.fs.openDirAbsolute(current_dir, .{ .iterate = true });
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (shouldSkipEntry(entry.name, entry.kind)) continue;

        const child_path = try std_compat.fs.path.join(allocator, &.{ current_dir, entry.name });
        defer allocator.free(child_path);

        switch (entry.kind) {
            .directory => try scanWorkspaceFiles(allocator, root_dir, child_path, options, findings),
            .file => try scanWorkspaceFile(allocator, root_dir, child_path, options, findings),
            else => {},
        }
    }
}

fn scanWorkspaceFile(
    allocator: Allocator,
    root_dir: []const u8,
    file_path: []const u8,
    options: Options,
    findings: *std.ArrayListUnmanaged(Finding),
) !void {
    const rel_path = try std_compat.fs.path.relative(allocator, root_dir, file_path);
    defer allocator.free(rel_path);

    if (shouldIgnorePath(rel_path, options.exclude_patterns)) return;

    const contents = fs_compat.readFileAlloc(std_compat.fs.cwd(), allocator, file_path, MAX_SCAN_FILE_BYTES) catch |err| switch (err) {
        error.StreamTooLong => return,
        error.FileNotFound => return,
        else => return err,
    };
    defer allocator.free(contents);

    if (isProbablyBinary(contents)) return;
    try scanText(allocator, rel_path, contents, .workspace_file, options, findings);
}

fn scanStagedDiff(
    allocator: Allocator,
    diff: []const u8,
    options: Options,
    findings: *std.ArrayListUnmanaged(Finding),
) !void {
    var current_file: ?[]const u8 = null;
    var current_line: ?usize = null;

    var it = std.mem.splitScalar(u8, diff, '\n');
    while (it.next()) |raw_line| {
        const line = std_compat.mem.trimRight(u8, raw_line, "\r");
        if (std.mem.startsWith(u8, line, "+++ ")) {
            current_file = parseDiffPath(line);
            current_line = null;
            continue;
        }
        if (std.mem.startsWith(u8, line, "@@")) {
            current_line = parseAddedHunkStart(line);
            continue;
        }
        if (current_file == null or current_line == null) continue;
        if (line.len == 0) continue;

        switch (line[0]) {
            '+' => {
                if (std.mem.startsWith(u8, line, "+++")) continue;
                try scanDiffLine(allocator, current_file.?, current_line.?, line[1..], options, findings);
                current_line.? += 1;
            },
            ' ' => current_line.? += 1,
            else => {},
        }
    }
}

fn scanGitHistoryDiff(
    allocator: Allocator,
    diff: []const u8,
    options: Options,
    findings: *std.ArrayListUnmanaged(Finding),
) !void {
    var current_file: ?[]const u8 = null;
    var current_line: ?usize = null;

    var it = std.mem.splitScalar(u8, diff, '\n');
    while (it.next()) |raw_line| {
        const line = std_compat.mem.trimRight(u8, raw_line, "\r");
        if (std.mem.startsWith(u8, line, "+++ ")) {
            current_file = parseDiffPath(line);
            current_line = null;
            continue;
        }
        if (std.mem.startsWith(u8, line, "@@")) {
            current_line = parseAddedHunkStart(line);
            continue;
        }
        if (current_file == null or current_line == null) continue;
        if (line.len == 0) continue;

        switch (line[0]) {
            '+' => {
                if (std.mem.startsWith(u8, line, "+++")) continue;
                try scanHistoryLine(allocator, current_file.?, current_line.?, line[1..], options, findings);
                current_line.? += 1;
            },
            ' ' => current_line.? += 1,
            else => {},
        }
    }
}

fn scanDiffLine(
    allocator: Allocator,
    path: []const u8,
    line_no: usize,
    line: []const u8,
    options: Options,
    findings: *std.ArrayListUnmanaged(Finding),
) !void {
    if (shouldIgnorePath(path, options.exclude_patterns)) return;
    if (detectLine(path, line, .git_staged_diff)) |rule| {
        try appendFinding(allocator, findings, options, rule, path, line_no, .git_staged_diff, line);
    }
}

fn scanHistoryLine(
    allocator: Allocator,
    path: []const u8,
    line_no: usize,
    line: []const u8,
    options: Options,
    findings: *std.ArrayListUnmanaged(Finding),
) !void {
    if (shouldIgnorePath(path, options.exclude_patterns)) return;
    if (detectLine(path, line, .git_history)) |rule| {
        try appendFinding(allocator, findings, options, rule, path, line_no, .git_history, line);
    }
}

fn scanText(
    allocator: Allocator,
    path: []const u8,
    text: []const u8,
    source: FindingSource,
    options: Options,
    findings: *std.ArrayListUnmanaged(Finding),
) !void {
    var line_no: usize = 1;
    var start: usize = 0;
    while (start <= text.len) {
        const end = std.mem.indexOfScalarPos(u8, text, start, '\n') orelse text.len;
        const line = std_compat.mem.trimRight(u8, text[start..end], "\r");
        if (detectLine(path, line, source)) |rule| {
            try appendFinding(allocator, findings, options, rule, path, line_no, source, line);
        }
        if (end == text.len) break;
        start = end + 1;
        line_no += 1;
    }
}

fn detectLine(path: []const u8, line: []const u8, source: FindingSource) ?DetectedRule {
    if (line.len == 0) return null;
    const path_category = classifyPath(path);

    if (containsPrivateKeyMarker(line)) {
        return .{ .severity = .critical, .confidence = .high, .rule = "private_key_block" };
    }

    if (hasCredentialUrl(line)) {
        return .{
            .severity = .high,
            .confidence = if (path_category == .docs or path_category == .code) .medium else .high,
            .rule = "credential_in_url",
        };
    }

    if (matchSecretAssignment(line)) |assignment| {
        return classifySecretAssignment(path, line, path_category, assignment);
    }

    if ((source == .git_staged_diff or source == .git_history) and hasTokenPrefix(line) and !looksPlaceholder(line)) {
        return .{ .severity = .high, .confidence = .high, .rule = "hardcoded_token" };
    }

    return null;
}

const AssignmentMatch = struct {
    key: []const u8,
    value: []const u8,
    quoted: bool,
};

fn matchSecretAssignment(line: []const u8) ?AssignmentMatch {
    const keywords = [_][]const u8{
        "api_key",
        "api-key",
        "apikey",
        "token",
        "password",
        "passwd",
        "secret",
        "api_secret",
        "access_key",
    };

    for (keywords) |keyword| {
        if (indexOfIgnoreCase(line, keyword)) |idx| {
            if (!keywordBoundaryOk(line, idx, keyword.len)) continue;

            var pos = idx + keyword.len;
            while (pos < line.len and (line[pos] == ' ' or line[pos] == '"' or line[pos] == '\'')) pos += 1;
            if (pos >= line.len or (line[pos] != '=' and line[pos] != ':')) continue;
            pos += 1;
            while (pos < line.len and (line[pos] == ' ' or line[pos] == '"' or line[pos] == '\'')) pos += 1;
            if (pos >= line.len) continue;
            const quoted = pos > 0 and (line[pos - 1] == '"' or line[pos - 1] == '\'');

            const value_start = pos;
            var value_end = value_start;
            while (value_end < line.len) : (value_end += 1) {
                const ch = line[value_end];
                if (ch == '"' or ch == '\'' or ch == ',' or ch == '#' or ch == ' ' or ch == '\t') break;
            }
            if (value_end <= value_start) continue;

            return .{
                .key = line[idx .. idx + keyword.len],
                .value = line[value_start..value_end],
                .quoted = quoted,
            };
        }
    }
    return null;
}

fn keywordBoundaryOk(line: []const u8, idx: usize, len: usize) bool {
    if (idx > 0) {
        const before = line[idx - 1];
        if (std.ascii.isAlphanumeric(before) or before == '_' or before == '-') return false;
    }
    if (idx + len < line.len) {
        const after = line[idx + len];
        if (std.ascii.isAlphanumeric(after) or after == '_' or after == '-') return false;
    }
    return true;
}

fn normalizeValue(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\"'");
}

fn isHighRiskKeyword(keyword: []const u8) bool {
    return eqlIgnoreCase(keyword, "password") or eqlIgnoreCase(keyword, "passwd");
}

fn containsPrivateKeyMarker(line: []const u8) bool {
    return std.mem.indexOf(u8, line, "-----BEGIN ") != null and std.mem.indexOf(u8, line, "PRIVATE KEY-----") != null;
}

fn hasCredentialUrl(line: []const u8) bool {
    const scheme_idx = std.mem.indexOf(u8, line, "://") orelse return false;
    const rest = line[scheme_idx + 3 ..];
    const authority_end = firstIndexAny(rest, "/?#") orelse rest.len;
    const authority = rest[0..authority_end];
    const at_idx = std.mem.indexOfScalar(u8, authority, '@') orelse return false;
    const userinfo = authority[0..at_idx];
    return std.mem.indexOfScalar(u8, userinfo, ':') != null;
}

fn hasTokenPrefix(text: []const u8) bool {
    for (token_prefixes) |prefix| {
        if (std.mem.indexOf(u8, text, prefix)) |idx| {
            const end = tokenEnd(text, idx + prefix.len);
            if (end > idx + prefix.len) {
                const token = text[idx..end];
                if (!looksPlaceholder(token)) return true;
            }
        }
    }
    return false;
}

fn tokenEnd(text: []const u8, start: usize) usize {
    var end = start;
    while (end < text.len) : (end += 1) {
        const ch = text[end];
        if (!(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == ':')) break;
    }
    return end;
}

fn looksPlaceholder(text: []const u8) bool {
    const trimmed = normalizeValue(text);
    if (trimmed.len == 0) return true;

    const lower = std.ascii.allocLowerString(std.heap.page_allocator, trimmed) catch return false;
    defer std.heap.page_allocator.free(lower);

    if (std.mem.startsWith(u8, lower, "${") or std.mem.startsWith(u8, lower, "{{") or std.mem.startsWith(u8, lower, "<")) return true;
    if (std.mem.indexOf(u8, lower, "example") != null) return true;
    if (std.mem.indexOf(u8, lower, "placeholder") != null) return true;
    if (std.mem.indexOf(u8, lower, "replace") != null) return true;
    if (std.mem.indexOf(u8, lower, "changeme") != null) return true;
    if (std.mem.indexOf(u8, lower, "dummy") != null) return true;
    if (std.mem.indexOf(u8, lower, "sample") != null) return true;
    if (std.mem.indexOf(u8, lower, "fake") != null) return true;
    if (std.mem.indexOf(u8, lower, "test") != null) return true;
    if (std.mem.eql(u8, lower, "null") or std.mem.eql(u8, lower, "false") or std.mem.eql(u8, lower, "true")) return true;
    return false;
}

fn appendFinding(
    allocator: Allocator,
    findings: *std.ArrayListUnmanaged(Finding),
    options: Options,
    rule: DetectedRule,
    path: []const u8,
    line_no: usize,
    source: FindingSource,
    raw_preview: []const u8,
) !void {
    if (options.only_secrets and rule.severity.rank() < Severity.high.rank()) return;

    try findings.append(allocator, .{
        .severity = rule.severity,
        .confidence = rule.confidence,
        .rule = try allocator.dupe(u8, rule.rule),
        .path = try allocator.dupe(u8, path),
        .line = line_no,
        .source = source,
        .preview = try buildPreview(allocator, raw_preview),
    });
}

fn buildPreview(allocator: Allocator, raw: []const u8) ![]u8 {
    const scrubbed = try scrub.scrubSecretPatterns(allocator, raw);
    if (scrubbed.len <= MAX_PREVIEW_CHARS) return scrubbed;

    const preview = util.previewUtf8(scrubbed, MAX_PREVIEW_CHARS);
    const out = try std.fmt.allocPrint(allocator, "{s}...", .{preview.slice});
    allocator.free(scrubbed);
    return out;
}

fn shouldSkipEntry(name: []const u8, kind: std_compat.fs.File.Kind) bool {
    if (kind == .directory) {
        for (skipped_dirs) |dir_name| {
            if (std.mem.eql(u8, name, dir_name)) return true;
        }
    }
    return false;
}

fn shouldIgnorePath(path: []const u8, exclude_patterns: []const []const u8) bool {
    for (ignored_path_prefixes) |prefix| {
        if (std.mem.startsWith(u8, path, prefix)) return true;
    }

    for (exclude_patterns) |pattern| {
        if (pattern.len == 0) continue;
        if (std.mem.indexOf(u8, path, pattern) != null) return true;
    }
    return false;
}

fn isProbablyBinary(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    if (std.mem.indexOfScalar(u8, bytes, 0) != null) return true;

    var suspicious: usize = 0;
    for (bytes) |ch| {
        if (ch < 0x09) suspicious += 1;
    }
    return suspicious > 8;
}

fn parseDiffPath(line: []const u8) ?[]const u8 {
    if (std.mem.startsWith(u8, line, "+++ b/")) return line[6..];
    return null;
}

fn parseAddedHunkStart(line: []const u8) ?usize {
    const plus_idx = std.mem.indexOfScalar(u8, line, '+') orelse return null;
    var end = plus_idx + 1;
    while (end < line.len and std.ascii.isDigit(line[end])) : (end += 1) {}
    if (end == plus_idx + 1) return null;
    return std.fmt.parseInt(usize, line[plus_idx + 1 .. end], 10) catch null;
}

fn containsText(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

fn classifyPath(path: []const u8) PathCategory {
    if (std.mem.startsWith(u8, path, "vendor/") or
        std.mem.startsWith(u8, path, "zig-pkg/") or
        std.mem.startsWith(u8, path, "node_modules/"))
    {
        return .vendor_like;
    }
    if (isDocumentationPath(path)) return .docs;
    if (isConfigLikePath(path)) return .config;
    if (isCodePath(path)) return .code;
    return .neutral;
}

fn classifySecretAssignment(
    path: []const u8,
    line: []const u8,
    path_category: PathCategory,
    assignment: AssignmentMatch,
) ?DetectedRule {
    const value = normalizeValue(assignment.value);
    if (value.len == 0 or looksPlaceholder(value)) return null;

    const known_token = hasTokenPrefix(value);
    const opaque_value = looksOpaqueSecretValue(value);
    const expression = looksLikeExpression(value) and !known_token and !opaque_value;
    const high_risk_keyword = isHighRiskKeyword(assignment.key);

    if (expression or looksLikeAccessorLine(line)) return null;

    switch (path_category) {
        .vendor_like => {
            if (!known_token) return null;
        },
        .docs => {
            if (!known_token and !(assignment.quoted and opaque_value)) return null;
        },
        .code => {
            if (!known_token and !(assignment.quoted and (opaque_value or high_risk_keyword))) return null;
        },
        .config => {
            if (!known_token and !opaque_value and !(high_risk_keyword and (assignment.quoted or value.len >= 8))) {
                return null;
            }
        },
        .neutral => {
            if (!known_token and !opaque_value and !(high_risk_keyword and (assignment.quoted or value.len >= 8))) {
                return null;
            }
        },
    }

    const severity: Severity = if (known_token or high_risk_keyword or (path_category == .config and opaque_value))
        .high
    else
        .medium;
    const confidence: Confidence = if (known_token)
        .high
    else switch (path_category) {
        .config => if (opaque_value or high_risk_keyword) .medium else .low,
        .neutral => if (opaque_value or high_risk_keyword) .medium else .low,
        .code => .medium,
        .docs => .low,
        .vendor_like => .medium,
    };

    return .{
        .severity = severity,
        .confidence = confidence,
        .rule = if (std.mem.indexOf(u8, path, ".env") != null) "env_secret_assignment" else "secret_assignment",
    };
}

fn isDocumentationPath(path: []const u8) bool {
    if (std.mem.startsWith(u8, path, "docs/") or std.mem.startsWith(u8, path, "reference/")) return true;

    const basename = std.fs.path.basename(path);
    if (eqlIgnoreCase(basename, "README") or eqlIgnoreCase(basename, "README.md")) return true;

    const ext = std.fs.path.extension(path);
    return eqlIgnoreCase(ext, ".md") or eqlIgnoreCase(ext, ".rst") or eqlIgnoreCase(ext, ".adoc");
}

fn isConfigLikePath(path: []const u8) bool {
    const basename = std.fs.path.basename(path);
    const ext = std.fs.path.extension(path);

    if (std.mem.startsWith(u8, basename, ".env")) return true;
    if (eqlIgnoreCase(ext, ".env") or eqlIgnoreCase(ext, ".pem") or eqlIgnoreCase(ext, ".key") or eqlIgnoreCase(ext, ".crt") or eqlIgnoreCase(ext, ".cer") or eqlIgnoreCase(ext, ".p12") or eqlIgnoreCase(ext, ".pfx")) {
        return true;
    }
    if (eqlIgnoreCase(ext, ".json") or eqlIgnoreCase(ext, ".yaml") or eqlIgnoreCase(ext, ".yml") or eqlIgnoreCase(ext, ".toml") or eqlIgnoreCase(ext, ".ini") or eqlIgnoreCase(ext, ".conf") or eqlIgnoreCase(ext, ".properties")) {
        return true;
    }
    return indexOfIgnoreCase(basename, "secret") != null or
        indexOfIgnoreCase(basename, "credential") != null or
        indexOfIgnoreCase(basename, "config") != null;
}

fn isCodePath(path: []const u8) bool {
    const ext = std.fs.path.extension(path);
    const code_exts = [_][]const u8{
        ".zig", ".c",    ".h",   ".cc",   ".cpp", ".hpp",   ".rs", ".go",  ".py", ".js",
        ".ts",  ".tsx",  ".jsx", ".java", ".kt",  ".swift", ".rb", ".php", ".cs", ".scala",
        ".sh",  ".bash", ".zsh",
    };
    for (code_exts) |code_ext| {
        if (eqlIgnoreCase(ext, code_ext)) return true;
    }
    return false;
}

fn looksOpaqueSecretValue(value: []const u8) bool {
    if (value.len < 16) return false;
    if (std.mem.indexOfAny(u8, value, " \t(){}[]") != null) return false;

    var alpha: usize = 0;
    var digit: usize = 0;
    var allowed: usize = 0;
    for (value) |ch| {
        if (std.ascii.isAlphabetic(ch)) alpha += 1;
        if (std.ascii.isDigit(ch)) digit += 1;
        if (std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_' or ch == '.' or ch == ':' or ch == '/' or ch == '+' or ch == '=') {
            allowed += 1;
        }
    }
    if (alpha == 0 or digit == 0) return false;
    return allowed * 100 >= value.len * 85;
}

fn looksLikeExpression(value: []const u8) bool {
    if (std.mem.indexOfScalar(u8, value, '(') != null or std.mem.indexOfScalar(u8, value, ')') != null) return true;
    if (std.mem.indexOf(u8, value, "std.") != null) return true;
    if (std.mem.indexOf(u8, value, ".get") != null) return true;
    if (std.mem.indexOf(u8, value, "trim") != null and std.mem.indexOfScalar(u8, value, '(') != null) return true;
    if (std.mem.indexOfScalar(u8, value, '{') != null or std.mem.indexOfScalar(u8, value, '}') != null) return true;
    return false;
}

fn looksLikeAccessorLine(line: []const u8) bool {
    return std.mem.indexOf(u8, line, ".get(\"authorization\")") != null or
        std.mem.indexOf(u8, line, ".get(\"token\")") != null or
        std.mem.indexOf(u8, line, ".headers.get(") != null;
}

fn eqlIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |lhs, rhs| {
        if (std.ascii.toLower(lhs) != std.ascii.toLower(rhs)) return false;
    }
    return true;
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0 or haystack.len < needle.len) return null;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }
    return null;
}

fn firstIndexAny(haystack: []const u8, any: []const u8) ?usize {
    for (haystack, 0..) |ch, idx| {
        if (std.mem.indexOfScalar(u8, any, ch) != null) return idx;
    }
    return null;
}

fn appendFmt(buf: *std.ArrayListUnmanaged(u8), allocator: Allocator, comptime fmt: []const u8, args: anytype) !void {
    const rendered = try std.fmt.allocPrint(allocator, fmt, args);
    defer allocator.free(rendered);
    try buf.appendSlice(allocator, rendered);
}

fn renderText(allocator: Allocator, report: Report, fail_on: FailureThreshold) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try appendFmt(&buf, allocator, "Workspace audit ({s})\n", .{report.scanned_source.toString()});
    try appendFmt(&buf, allocator, "Workspace: {s}\n", .{report.workspace_dir});
    if (report.repo_root) |root| {
        try appendFmt(&buf, allocator, "Repo root: {s}\n", .{root});
    }
    try appendFmt(&buf, allocator, "Fail on: {s}\n", .{fail_on.toString()});

    if (report.findings.len == 0) {
        try buf.appendSlice(allocator, "No findings detected.\n");
    } else {
        try buf.appendSlice(allocator, "\n");
        for (report.findings) |finding| {
            try appendFmt(&buf, allocator, "[{s}/{s}] {s}:{d} {s}\n", .{
                finding.severity.toString(),
                finding.confidence.toString(),
                finding.path,
                finding.line orelse 0,
                finding.rule,
            });
            try appendFmt(&buf, allocator, "  {s}\n\n", .{finding.preview});
        }
    }

    try appendFmt(&buf, allocator, "Summary: critical={d} high={d} medium={d}\n", .{
        report.critical_count,
        report.high_count,
        report.medium_count,
    });
    return try buf.toOwnedSlice(allocator);
}

fn renderJson(allocator: Allocator, report: Report, fail_on: FailureThreshold) ![]u8 {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    errdefer buf.deinit(allocator);

    try buf.appendSlice(allocator, "{");
    try json_util.appendJsonKeyValue(&buf, allocator, "workspace_dir", report.workspace_dir);
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKey(&buf, allocator, "repo_root");
    if (report.repo_root) |root| {
        try json_util.appendJsonString(&buf, allocator, root);
    } else {
        try buf.appendSlice(allocator, "null");
    }
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKeyValue(&buf, allocator, "scanned_source", report.scanned_source.toString());
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKeyValue(&buf, allocator, "fail_on", fail_on.toString());
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKey(&buf, allocator, "ok");
    try buf.appendSlice(allocator, if (report.exceedsThreshold(fail_on)) "false" else "true");
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonKey(&buf, allocator, "counts");
    try buf.appendSlice(allocator, "{");
    try json_util.appendJsonInt(&buf, allocator, "critical", @intCast(report.critical_count));
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonInt(&buf, allocator, "high", @intCast(report.high_count));
    try buf.appendSlice(allocator, ",");
    try json_util.appendJsonInt(&buf, allocator, "medium", @intCast(report.medium_count));
    try buf.appendSlice(allocator, "},");
    try json_util.appendJsonKey(&buf, allocator, "findings");
    try buf.appendSlice(allocator, "[");
    for (report.findings, 0..) |finding, idx| {
        if (idx > 0) try buf.appendSlice(allocator, ",");
        try buf.appendSlice(allocator, "{");
        try json_util.appendJsonKeyValue(&buf, allocator, "severity", finding.severity.toString());
        try buf.appendSlice(allocator, ",");
        try json_util.appendJsonKeyValue(&buf, allocator, "confidence", finding.confidence.toString());
        try buf.appendSlice(allocator, ",");
        try json_util.appendJsonKeyValue(&buf, allocator, "rule", finding.rule);
        try buf.appendSlice(allocator, ",");
        try json_util.appendJsonKeyValue(&buf, allocator, "path", finding.path);
        try buf.appendSlice(allocator, ",");
        try json_util.appendJsonKey(&buf, allocator, "line");
        if (finding.line) |line_no| {
            try appendFmt(&buf, allocator, "{d}", .{line_no});
        } else {
            try buf.appendSlice(allocator, "null");
        }
        try buf.appendSlice(allocator, ",");
        try json_util.appendJsonKeyValue(&buf, allocator, "source", finding.source.toString());
        try buf.appendSlice(allocator, ",");
        try json_util.appendJsonKeyValue(&buf, allocator, "preview", finding.preview);
        try buf.appendSlice(allocator, "}");
    }
    try buf.appendSlice(allocator, "]}");
    return try buf.toOwnedSlice(allocator);
}

test "detect private key block as critical" {
    const rule = detectLine("id_rsa", "-----BEGIN PRIVATE KEY-----", .workspace_file).?;
    try std.testing.expectEqual(Severity.critical, rule.severity);
    try std.testing.expectEqualStrings("private_key_block", rule.rule);
}

test "workspace audit finds env secret assignment" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std_compat.fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = ".env",
        .data = "API_KEY=sk-live-1234567890abcdef\n",
    });

    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    var report = try buildReport(std.testing.allocator, workspace, .{
        .workspace_dir = workspace,
    });
    defer report.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 1), report.findings.len);
    try std.testing.expectEqual(Severity.high, report.findings[0].severity);
    try std.testing.expectEqual(Confidence.high, report.findings[0].confidence);
    try std.testing.expectEqualStrings(".env", report.findings[0].path);
}

test "workspace audit ignores code variable token assignment" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std_compat.fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = "build.zig",
        .data = "const token = std.mem.trim(u8, token_raw, \" \\t\\r\\n\");\n",
    });

    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    var report = try buildReport(std.testing.allocator, workspace, .{
        .workspace_dir = workspace,
    });
    defer report.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), report.findings.len);
}

test "workspace audit excludes requested paths" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std_compat.fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = ".env",
        .data = "API_KEY=sk-live-1234567890abcdef\n",
    });

    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    var report = try buildReport(std.testing.allocator, workspace, .{
        .workspace_dir = workspace,
        .exclude_patterns = &.{".env"},
    });
    defer report.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), report.findings.len);
}

test "workspace audit only secrets hides medium findings" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std_compat.fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = "notes.txt",
        .data = "secret: abcdef1234567890\n",
    });

    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    var report = try buildReport(std.testing.allocator, workspace, .{
        .workspace_dir = workspace,
        .only_secrets = true,
    });
    defer report.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), report.findings.len);
}

test "workspace audit ignores vendored paths by default" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try std_compat.fs.Dir.wrap(tmp.dir).makePath("zig-pkg/pkg");
    try std_compat.fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = "zig-pkg/pkg/README.md",
        .data = "token=ghp_abcd1234567890secret\n",
    });

    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    var report = try buildReport(std.testing.allocator, workspace, .{
        .workspace_dir = workspace,
    });
    defer report.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 0), report.findings.len);
}

fn gitAvailable(allocator: Allocator) bool {
    const result = process_util.run(allocator, &.{ "git", "--version" }, .{
        .max_output_bytes = 16 * 1024,
    }) catch return false;
    defer result.deinit(allocator);
    return result.success;
}

test "workspace audit staged diff finds raw token in added line" {
    if (!gitAvailable(std.testing.allocator)) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    {
        const init = try process_util.run(std.testing.allocator, &.{ "git", "init" }, .{
            .cwd = workspace,
            .max_output_bytes = 64 * 1024,
        });
        defer init.deinit(std.testing.allocator);
        if (!init.success) return error.SkipZigTest;
    }

    try std_compat.fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = "config.txt",
        .data = "Bearer ghp_abcd1234567890secret\n",
    });

    {
        const add = try process_util.run(std.testing.allocator, &.{ "git", "add", "config.txt" }, .{
            .cwd = workspace,
            .max_output_bytes = 64 * 1024,
        });
        defer add.deinit(std.testing.allocator);
        if (!add.success) return error.SkipZigTest;
    }

    var report = try buildReport(std.testing.allocator, workspace, .{
        .workspace_dir = workspace,
        .staged = true,
    });
    defer report.deinit(std.testing.allocator);

    try std.testing.expect(report.findings.len >= 1);
    try std.testing.expectEqual(FindingSource.git_staged_diff, report.findings[0].source);
}

test "workspace audit commit scan finds token in history diff" {
    if (!gitAvailable(std.testing.allocator)) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    {
        const init = try process_util.run(std.testing.allocator, &.{ "git", "init" }, .{
            .cwd = workspace,
            .max_output_bytes = 64 * 1024,
        });
        defer init.deinit(std.testing.allocator);
        if (!init.success) return error.SkipZigTest;
    }

    {
        const email = try process_util.run(std.testing.allocator, &.{ "git", "config", "user.email", "audit-demo@example.test" }, .{
            .cwd = workspace,
            .max_output_bytes = 64 * 1024,
        });
        defer email.deinit(std.testing.allocator);
        if (!email.success) return error.SkipZigTest;
    }
    {
        const name = try process_util.run(std.testing.allocator, &.{ "git", "config", "user.name", "Audit Demo" }, .{
            .cwd = workspace,
            .max_output_bytes = 64 * 1024,
        });
        defer name.deinit(std.testing.allocator);
        if (!name.success) return error.SkipZigTest;
    }

    try std_compat.fs.Dir.wrap(tmp.dir).writeFile(.{
        .sub_path = "history.env",
        .data = "API_KEY=sk-history1234567890abcdefghijklmnop\n",
    });

    {
        const add = try process_util.run(std.testing.allocator, &.{ "git", "add", "history.env" }, .{
            .cwd = workspace,
            .max_output_bytes = 64 * 1024,
        });
        defer add.deinit(std.testing.allocator);
        if (!add.success) return error.SkipZigTest;
    }
    {
        const commit = try process_util.run(std.testing.allocator, &.{ "git", "commit", "-m", "add history secret fixture" }, .{
            .cwd = workspace,
            .max_output_bytes = 64 * 1024,
        });
        defer commit.deinit(std.testing.allocator);
        if (!commit.success) return error.SkipZigTest;
    }

    const rev = try process_util.run(std.testing.allocator, &.{ "git", "rev-parse", "HEAD" }, .{
        .cwd = workspace,
        .max_output_bytes = 64 * 1024,
    });
    defer rev.deinit(std.testing.allocator);
    if (!rev.success) return error.SkipZigTest;

    const commit_sha = std.mem.trim(u8, rev.stdout, " \r\n\t");
    var report = try buildReport(std.testing.allocator, workspace, .{
        .workspace_dir = workspace,
        .commit = commit_sha,
    });
    defer report.deinit(std.testing.allocator);

    try std.testing.expect(report.findings.len >= 1);
    try std.testing.expectEqual(FindingSource.git_history, report.findings[0].source);
}

test "failure threshold none never fails" {
    var findings = try std.testing.allocator.alloc(Finding, 1);
    findings[0] = Finding{
        .severity = .critical,
        .confidence = .high,
        .rule = try std.testing.allocator.dupe(u8, "private_key_block"),
        .path = try std.testing.allocator.dupe(u8, ".env"),
        .line = 1,
        .source = .workspace_file,
        .preview = try std.testing.allocator.dupe(u8, "preview"),
    };
    var report = Report{
        .workspace_dir = "/tmp/ws",
        .repo_root = null,
        .findings = findings,
        .critical_count = 1,
        .scanned_source = .workspace_file,
    };
    defer report.deinit(std.testing.allocator);

    try std.testing.expect(!report.exceedsThreshold(.none));
    try std.testing.expect(report.exceedsThreshold(.critical));
}
