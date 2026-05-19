//! Read-only SQLite analytics tool.
//!
//! Three layers of defense against accidental writes:
//!   1. Statement classifier — Zig-side allowlist for SELECT / WITH / PRAGMA table_info
//!   2. SQLITE_OPEN_READONLY — engine cannot perform writes physically
//!   3. sqlite3_stmt_readonly() — backstop check after prepare
//!
//! Output is bounded by row count and total bytes.

const std = @import("std");
const std_compat = @import("compat");
const fs_compat = @import("../fs_compat.zig");
const root = @import("root.zig");
const path_security = @import("path_security.zig");
const redaction = @import("../redaction.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

pub const c = @cImport({
    @cInclude("sqlite3.h");
});

const SQLITE_STATIC: c.sqlite3_destructor_type = null;
const BUSY_TIMEOUT_MS: c_int = 1000;
const DEFAULT_MAX_RESULT_BYTES: usize = 256 * 1024;
const DEFAULT_MAX_RESULT_ROWS: u32 = 1000;

pub const SqliteQueryTool = struct {
    workspace_dir: []const u8,
    allowed_paths: []const []const u8 = &.{},
    max_result_bytes: usize = DEFAULT_MAX_RESULT_BYTES,
    max_result_rows: u32 = DEFAULT_MAX_RESULT_ROWS,

    pub const tool_name = "sqlite_query";
    pub const tool_description =
        "Run a read-only SQL query against a SQLite database in the workspace. " ++
        "Only SELECT, WITH, and PRAGMA table_info statements are permitted. " ++
        "Common text transform / encoding functions that can bypass redaction are rejected. " ++
        "Returns a PII-redacted JSON object {columns, rows, row_count, truncated}. " ++
        "Bounded by max_rows and an internal byte cap. Multi-statement input is rejected.";
    pub const tool_params =
        \\{"type":"object","properties":{"db_path":{"type":"string","description":"Workspace-relative path to the .db file."},"query":{"type":"string","description":"Single SELECT/WITH/PRAGMA table_info statement (no semicolons mid-stream)."},"max_rows":{"type":"integer","description":"Optional row cap (1..1000). Default: 1000."}},"required":["db_path","query"]}
    ;

    pub const vtable = root.ToolVTable(@This());

    pub fn tool(self: *SqliteQueryTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *SqliteQueryTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const db_path_arg = root.getString(args, "db_path") orelse {
            return failOwned(allocator, "missing required parameter: db_path");
        };
        const query = root.getString(args, "query") orelse {
            return failOwned(allocator, "missing required parameter: query");
        };
        const max_rows: u32 = blk: {
            if (root.getInt(args, "max_rows")) |v| {
                // Schema declares max_rows >= 1; reject explicit non-positive values
                // (rather than silently coercing) so the schema and impl agree.
                if (v <= 0) {
                    return failOwned(allocator, "max_rows must be >= 1");
                }
                const clamped = @min(v, @as(i64, @intCast(self.max_result_rows)));
                break :blk @intCast(clamped);
            }
            break :blk self.max_result_rows;
        };
        if (root.getBool(args, "include_sensitive") orelse false) {
            return failOwned(allocator, "include_sensitive is not available in the agent sqlite_query tool");
        }

        // Layer 1a: path safety (rejects absolute, traversal, null bytes).
        //
        // Stricter than file_read on purpose: db_path must be workspace-relative;
        // absolute paths are never accepted even if a matching prefix is listed
        // in allowed_paths. Keeps analytics-time access narrow — to read a DB
        // outside the workspace, mount/symlink it under the workspace explicitly.
        if (!path_security.isPathSafe(db_path_arg)) {
            return failOwned(allocator, "db_path failed safety check (must be relative, no traversal, no null bytes)");
        }

        // Layer 1b: resolve absolute path; ensure it is inside workspace or allowed_paths
        const joined = try std.fs.path.join(allocator, &.{ self.workspace_dir, db_path_arg });
        defer allocator.free(joined);

        const resolved = fs_compat.realpathAllocPath(allocator, joined) catch |err| {
            return failOwnedFmt(allocator, "could not resolve db_path: {s}", .{@errorName(err)});
        };
        defer allocator.free(resolved);

        const ws_resolved = fs_compat.realpathAllocPath(allocator, self.workspace_dir) catch |err| {
            return failOwnedFmt(allocator, "could not resolve workspace_dir: {s}", .{@errorName(err)});
        };
        defer allocator.free(ws_resolved);

        if (!path_security.isResolvedPathAllowed(allocator, resolved, ws_resolved, self.allowed_paths)) {
            return failOwned(allocator, "db_path is outside workspace and allowed_paths");
        }

        // Layer 1c: statement classifier (allowlist)
        if (classifyStatement(query)) |err_msg| {
            return failOwned(allocator, err_msg);
        }

        // Layer 2: open DB read-only — engine refuses any write attempt
        var db: ?*c.sqlite3 = null;
        const path_z = try allocator.dupeZ(u8, resolved);
        defer allocator.free(path_z);
        const open_rc = c.sqlite3_open_v2(path_z.ptr, &db, c.SQLITE_OPEN_READONLY, null);
        if (open_rc != c.SQLITE_OK) {
            const err_msg_raw = if (db) |d| std.mem.span(c.sqlite3_errmsg(d)) else "open failed";
            const out_msg = try std.fmt.allocPrint(allocator, "open failed: {s}", .{err_msg_raw});
            if (db) |d| _ = c.sqlite3_close(d);
            return ToolResult{ .success = false, .output = out_msg };
        }
        defer _ = c.sqlite3_close(db);
        _ = c.sqlite3_busy_timeout(db, BUSY_TIMEOUT_MS);

        // Prepare statement
        const query_z = try allocator.dupeZ(u8, query);
        defer allocator.free(query_z);
        var stmt: ?*c.sqlite3_stmt = null;
        const prep_rc = c.sqlite3_prepare_v2(db, query_z.ptr, -1, &stmt, null);
        if (prep_rc != c.SQLITE_OK) {
            const err_msg = std.mem.span(c.sqlite3_errmsg(db));
            const out_msg = try std.fmt.allocPrint(allocator, "prepare failed: {s}", .{err_msg});
            return ToolResult{ .success = false, .output = out_msg };
        }
        defer _ = c.sqlite3_finalize(stmt);

        // Layer 3: backstop sqlite3_stmt_readonly check
        if (c.sqlite3_stmt_readonly(stmt) == 0) {
            return failOwned(allocator, "statement is not read-only (sqlite3_stmt_readonly check)");
        }

        return try renderRows(allocator, stmt.?, max_rows, self.max_result_bytes);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Statement classifier
// ════════════════════════════════════════════════════════════════════════════

/// Returns null if the statement passes the allowlist, otherwise a static
/// reason. The classifier is conservative — it never tries to fully parse
/// SQL, only check the leading keyword + reject mid-stream semicolons.
fn classifyStatement(query: []const u8) ?[]const u8 {
    const trimmed = stripCommentsAndWhitespace(query);
    if (trimmed.len == 0) return "empty query";

    // Multi-statement guard: a semicolon followed by anything but whitespace
    // and comments is a second statement and is rejected.
    {
        var i: usize = 0;
        while (i < trimmed.len) : (i += 1) {
            if (trimmed[i] == ';') {
                const rest = stripCommentsAndWhitespace(trimmed[i + 1 ..]);
                if (rest.len != 0) return "multi-statement queries are not allowed";
            }
        }
    }

    const first = firstKeyword(trimmed) orelse return "could not parse first keyword";
    if (eqIgnoreCase(first, "SELECT")) {
        if (findForbiddenRedactionBypassFunction(trimmed)) |_| {
            return "SQL text transform / encoding functions are not allowed in sqlite_query";
        }
        return null;
    }
    if (eqIgnoreCase(first, "WITH")) {
        // CTE — accept; sqlite3_stmt_readonly will catch any write inside it
        if (findForbiddenRedactionBypassFunction(trimmed)) |_| {
            return "SQL text transform / encoding functions are not allowed in sqlite_query";
        }
        return null;
    }
    if (eqIgnoreCase(first, "PRAGMA")) {
        const after_pragma = std.mem.trimStart(u8, trimmed[first.len..], " \t\r\n");
        const second = firstKeyword(after_pragma) orelse return "only PRAGMA table_info is allowed";
        if (!eqIgnoreCase(second, "table_info")) return "only PRAGMA table_info is allowed";
        // After "table_info" only `(` (function-call form) or end-of-statement
        // (followed by optional comments/whitespace) is permitted. This rejects
        // hypothetical forwards-compatibility names like `table_info_ext` and
        // similar look-alikes.
        const after_kw = std.mem.trimStart(u8, after_pragma[second.len..], " \t\r\n");
        if (after_kw.len == 0) return null;
        if (after_kw[0] == '(') return null;
        if (after_kw[0] == ';') return null;
        return "only PRAGMA table_info is allowed";
    }
    return "only SELECT, WITH, or PRAGMA table_info statements are allowed";
}

fn skipSqlQuoted(sql: []const u8, start: usize, quote: u8) usize {
    var i = start + 1;
    while (i < sql.len) : (i += 1) {
        if (sql[i] != quote) continue;
        if (i + 1 < sql.len and sql[i + 1] == quote) {
            i += 1;
            continue;
        }
        return i + 1;
    }
    return sql.len;
}

fn skipSqlBracketIdentifier(sql: []const u8, start: usize) usize {
    var i = start + 1;
    while (i < sql.len) : (i += 1) {
        if (sql[i] == ']') return i + 1;
    }
    return sql.len;
}

fn skipSqlTrivia(sql: []const u8, start: usize) usize {
    var i = start;
    while (i < sql.len) {
        const ch = sql[i];
        if (ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n') {
            i += 1;
            continue;
        }
        if (i + 1 < sql.len and ch == '-' and sql[i + 1] == '-') {
            i += 2;
            while (i < sql.len and sql[i] != '\n') i += 1;
            continue;
        }
        if (i + 1 < sql.len and ch == '/' and sql[i + 1] == '*') {
            i += 2;
            while (i + 1 < sql.len and !(sql[i] == '*' and sql[i + 1] == '/')) i += 1;
            if (i + 1 < sql.len) i += 2;
            continue;
        }
        return i;
    }
    return i;
}

fn isSqlIdentifierStart(ch: u8) bool {
    return std.ascii.isAlphabetic(ch) or ch == '_';
}

fn isSqlIdentifierContinue(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_';
}

fn isForbiddenRedactionBypassFunction(name: []const u8) bool {
    const functions = [_][]const u8{
        "hex",
        "quote",
        "printf",
        "substr",
        "substring",
        "replace",
        "unicode",
        "char",
        "lower",
        "upper",
        "json_quote",
    };
    for (functions) |function_name| {
        if (eqIgnoreCase(name, function_name)) return true;
    }
    return false;
}

fn findForbiddenRedactionBypassFunction(sql: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (i < sql.len) {
        const ch = sql[i];
        if (ch == '\'' or ch == '"' or ch == '`') {
            i = skipSqlQuoted(sql, i, ch);
            continue;
        }
        if (ch == '[') {
            i = skipSqlBracketIdentifier(sql, i);
            continue;
        }
        if (i + 1 < sql.len and ch == '-' and sql[i + 1] == '-') {
            i += 2;
            while (i < sql.len and sql[i] != '\n') i += 1;
            continue;
        }
        if (i + 1 < sql.len and ch == '/' and sql[i + 1] == '*') {
            i += 2;
            while (i + 1 < sql.len and !(sql[i] == '*' and sql[i + 1] == '/')) i += 1;
            if (i + 1 < sql.len) i += 2;
            continue;
        }
        if (!isSqlIdentifierStart(ch)) {
            i += 1;
            continue;
        }

        const start = i;
        i += 1;
        while (i < sql.len and isSqlIdentifierContinue(sql[i])) i += 1;
        const ident = sql[start..i];
        const call_pos = skipSqlTrivia(sql, i);
        if (call_pos < sql.len and sql[call_pos] == '(' and isForbiddenRedactionBypassFunction(ident)) {
            return ident;
        }
    }
    return null;
}

fn stripCommentsAndWhitespace(s: []const u8) []const u8 {
    var i: usize = 0;
    while (i < s.len) {
        const ch = s[i];
        if (ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n') {
            i += 1;
            continue;
        }
        if (i + 1 < s.len and ch == '-' and s[i + 1] == '-') {
            // -- line comment until newline
            while (i < s.len and s[i] != '\n') i += 1;
            continue;
        }
        if (i + 1 < s.len and ch == '/' and s[i + 1] == '*') {
            // /* block comment */
            i += 2;
            while (i + 1 < s.len and !(s[i] == '*' and s[i + 1] == '/')) i += 1;
            if (i + 1 < s.len) i += 2;
            continue;
        }
        return s[i..];
    }
    return s[s.len..];
}

fn firstKeyword(s: []const u8) ?[]const u8 {
    var end: usize = 0;
    while (end < s.len) : (end += 1) {
        const ch = s[end];
        if (!std.ascii.isAlphabetic(ch) and ch != '_') break;
    }
    if (end == 0) return null;
    return s[0..end];
}

fn eqIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
    }
    return true;
}

// ════════════════════════════════════════════════════════════════════════════
// Row rendering
// ════════════════════════════════════════════════════════════════════════════

const RESULT_FOOTER_RESERVE: usize = 96;

fn appendBoundedSlice(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    max_bytes: usize,
    s: []const u8,
) !void {
    if (out.items.len + s.len > max_bytes) return error.OutputLimitExceeded;
    try out.appendSlice(allocator, s);
}

fn appendBoundedByte(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    max_bytes: usize,
    b: u8,
) !void {
    if (out.items.len + 1 > max_bytes) return error.OutputLimitExceeded;
    try out.append(allocator, b);
}

fn renderTruncatedEmptyRows(allocator: std.mem.Allocator) !ToolResult {
    return .{
        .success = true,
        .output = try allocator.dupe(u8, "{\"columns\":[],\"rows\":[],\"row_count\":0,\"truncated\":true}"),
    };
}

fn renderTruncatedAfterDeinit(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8)) !ToolResult {
    out.deinit(allocator);
    return renderTruncatedEmptyRows(allocator);
}

fn renderRows(
    allocator: std.mem.Allocator,
    stmt: *c.sqlite3_stmt,
    max_rows: u32,
    max_bytes: usize,
) !ToolResult {
    const col_count: usize = @intCast(c.sqlite3_column_count(stmt));
    const row_budget = if (max_bytes > RESULT_FOOTER_RESERVE) max_bytes - RESULT_FOOTER_RESERVE else max_bytes;

    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(allocator);

    appendBoundedSlice(allocator, &out, row_budget, "{\"columns\":[") catch |err| switch (err) {
        error.OutputLimitExceeded => return renderTruncatedAfterDeinit(allocator, &out),
        else => return err,
    };
    var ci: usize = 0;
    while (ci < col_count) : (ci += 1) {
        if (ci > 0) appendBoundedByte(allocator, &out, row_budget, ',') catch |err| switch (err) {
            error.OutputLimitExceeded => return renderTruncatedAfterDeinit(allocator, &out),
            else => return err,
        };
        const name_raw = c.sqlite3_column_name(stmt, @intCast(ci));
        const name = if (name_raw == null) "" else std.mem.span(name_raw);
        appendJsonStringBounded(allocator, &out, row_budget, name) catch |err| switch (err) {
            error.OutputLimitExceeded => return renderTruncatedAfterDeinit(allocator, &out),
            else => return err,
        };
    }
    appendBoundedSlice(allocator, &out, row_budget, "],\"rows\":[") catch |err| switch (err) {
        error.OutputLimitExceeded => return renderTruncatedAfterDeinit(allocator, &out),
        else => return err,
    };

    var row_count: u32 = 0;
    var truncated = false;

    row_loop: while (true) {
        const rc = c.sqlite3_step(stmt);
        if (rc == c.SQLITE_DONE) break;
        if (rc != c.SQLITE_ROW) {
            const err_msg = std.mem.span(c.sqlite3_errmsg(c.sqlite3_db_handle(stmt)));
            const out_msg = try std.fmt.allocPrint(allocator, "step failed: {s}", .{err_msg});
            out.deinit(allocator);
            return ToolResult{ .success = false, .output = out_msg };
        }

        if (row_count >= max_rows) {
            truncated = true;
            break;
        }
        if (out.items.len >= max_bytes) {
            truncated = true;
            break;
        }

        // Track length BEFORE the row's leading comma so a single fat row
        // (e.g. one wide TEXT/BLOB cell) can be rolled back if it pushes
        // total output past max_bytes. Without this, max_bytes would be a
        // per-row check only, and one giant cell could blow the cap by
        // arbitrary margin.
        const row_start_len = out.items.len;
        if (row_count > 0) appendBoundedByte(allocator, &out, row_budget, ',') catch |err| switch (err) {
            error.OutputLimitExceeded => {
                truncated = true;
                break :row_loop;
            },
            else => return err,
        };
        appendBoundedByte(allocator, &out, row_budget, '[') catch |err| switch (err) {
            error.OutputLimitExceeded => {
                out.items.len = row_start_len;
                truncated = true;
                break :row_loop;
            },
            else => return err,
        };
        var col: c_int = 0;
        while (col < @as(c_int, @intCast(col_count))) : (col += 1) {
            if (col > 0) appendBoundedByte(allocator, &out, row_budget, ',') catch |err| switch (err) {
                error.OutputLimitExceeded => {
                    out.items.len = row_start_len;
                    truncated = true;
                    break :row_loop;
                },
                else => return err,
            };
            appendCellAsJson(allocator, &out, row_budget, stmt, col) catch |err| switch (err) {
                error.OutputLimitExceeded => {
                    out.items.len = row_start_len;
                    truncated = true;
                    break :row_loop;
                },
                else => return err,
            };
            if (truncated) break;
        }
        if (truncated) break;
        appendBoundedByte(allocator, &out, row_budget, ']') catch |err| switch (err) {
            error.OutputLimitExceeded => {
                out.items.len = row_start_len;
                truncated = true;
                break :row_loop;
            },
            else => return err,
        };
        if (out.items.len > max_bytes) {
            // Roll back this row entirely (including its leading comma).
            out.items.len = row_start_len;
            truncated = true;
            break;
        }
        row_count += 1;
    }

    try appendBoundedSlice(allocator, &out, max_bytes, "],\"row_count\":");
    var num_buf: [32]u8 = undefined;
    const rc_str = try std.fmt.bufPrint(&num_buf, "{d}", .{row_count});
    try appendBoundedSlice(allocator, &out, max_bytes, rc_str);
    try appendBoundedSlice(allocator, &out, max_bytes, ",\"truncated\":");
    try appendBoundedSlice(allocator, &out, max_bytes, if (truncated) "true" else "false");
    try appendBoundedByte(allocator, &out, max_bytes, '}');

    const rendered = try out.toOwnedSlice(allocator);
    var r = redaction.Redactor.init(allocator, .{});
    defer r.deinit();
    const redacted = try r.redact(allocator, rendered);
    allocator.free(rendered);
    if (redacted.len > max_bytes) {
        // Regression: redaction can expand short values such as a@b.co into
        // placeholders, so the public byte cap must apply after redaction too.
        allocator.free(redacted);
        return renderTruncatedEmptyRows(allocator);
    }
    return ToolResult{ .success = true, .output = redacted };
}

fn appendCellAsJson(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    max_bytes: usize,
    stmt: *c.sqlite3_stmt,
    col: c_int,
) !void {
    const col_type = c.sqlite3_column_type(stmt, col);
    switch (col_type) {
        c.SQLITE_NULL => try appendBoundedSlice(allocator, out, max_bytes, "null"),
        c.SQLITE_INTEGER => {
            const v = c.sqlite3_column_int64(stmt, col);
            var buf: [32]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "{d}", .{v});
            try appendBoundedSlice(allocator, out, max_bytes, s);
        },
        c.SQLITE_FLOAT => {
            const v = c.sqlite3_column_double(stmt, col);
            var buf: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "{d}", .{v});
            try appendBoundedSlice(allocator, out, max_bytes, s);
        },
        c.SQLITE_TEXT => {
            const raw = c.sqlite3_column_text(stmt, col);
            const len: usize = @intCast(c.sqlite3_column_bytes(stmt, col));
            const slice = if (raw == null) ""[0..] else @as([*]const u8, @ptrCast(raw))[0..len];
            try appendJsonStringBounded(allocator, out, max_bytes, slice);
        },
        c.SQLITE_BLOB => {
            const len: usize = @intCast(c.sqlite3_column_bytes(stmt, col));
            try appendBoundedSlice(allocator, out, max_bytes, "\"<blob:");
            var buf: [32]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "{d}", .{len});
            try appendBoundedSlice(allocator, out, max_bytes, s);
            try appendBoundedSlice(allocator, out, max_bytes, ">\"");
        },
        else => try appendBoundedSlice(allocator, out, max_bytes, "null"),
    }
}

fn appendJsonStringBounded(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    max_bytes: usize,
    s: []const u8,
) !void {
    try appendBoundedByte(allocator, out, max_bytes, '"');
    for (s) |ch| {
        switch (ch) {
            '"' => try appendBoundedSlice(allocator, out, max_bytes, "\\\""),
            '\\' => try appendBoundedSlice(allocator, out, max_bytes, "\\\\"),
            '\n' => try appendBoundedSlice(allocator, out, max_bytes, "\\n"),
            '\r' => try appendBoundedSlice(allocator, out, max_bytes, "\\r"),
            '\t' => try appendBoundedSlice(allocator, out, max_bytes, "\\t"),
            else => {
                if (ch < 0x20) {
                    var buf: [8]u8 = undefined;
                    const formatted = try std.fmt.bufPrint(&buf, "\\u{x:0>4}", .{ch});
                    try appendBoundedSlice(allocator, out, max_bytes, formatted);
                } else {
                    try appendBoundedByte(allocator, out, max_bytes, ch);
                }
            },
        }
    }
    try appendBoundedByte(allocator, out, max_bytes, '"');
}

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

const TestDb = struct {
    fn populate(path: [*:0]const u8) !void {
        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.OpenFailed;
        }
        defer _ = c.sqlite3_close(db);
        const sql =
            "CREATE TABLE u (id INTEGER PRIMARY KEY, name TEXT, age INTEGER, score REAL, picture BLOB);" ++
            "INSERT INTO u (id, name, age, score, picture) VALUES (1, 'alice', 30, 9.5, X'00FF00');" ++
            "INSERT INTO u (id, name, age, score) VALUES (2, 'bob', 25, 7.25);" ++
            "INSERT INTO u (id, name, age) VALUES (3, NULL, 40);";
        if (c.sqlite3_exec(db, sql, null, null, null) != c.SQLITE_OK) return error.PopulateFailed;
    }

    fn populateMany(path: [*:0]const u8, n: usize) !void {
        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.OpenFailed;
        }
        defer _ = c.sqlite3_close(db);
        if (c.sqlite3_exec(db, "CREATE TABLE big (id INTEGER, payload TEXT);", null, null, null) != c.SQLITE_OK) {
            return error.PopulateFailed;
        }
        var i: usize = 0;
        while (i < n) : (i += 1) {
            var buf: [128]u8 = undefined;
            const sql = try std.fmt.bufPrintZ(&buf, "INSERT INTO big VALUES ({d}, 'row{d}');", .{ i, i });
            if (c.sqlite3_exec(db, sql.ptr, null, null, null) != c.SQLITE_OK) return error.PopulateFailed;
        }
    }

    fn populateSensitive(path: [*:0]const u8) !void {
        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.OpenFailed;
        }
        defer _ = c.sqlite3_close(db);
        const sql =
            "CREATE TABLE sensitive (email TEXT, card TEXT, api_token TEXT);" ++
            "INSERT INTO sensitive VALUES ('alice@example.com', '4111 1111 1111 1111', 'api_key=sk-live-secret');";
        if (c.sqlite3_exec(db, sql, null, null, null) != c.SQLITE_OK) return error.PopulateFailed;
    }

    fn populateHugeText(path: [*:0]const u8, allocator: std.mem.Allocator, len: usize) !void {
        var db: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open(path, &db);
        if (rc != c.SQLITE_OK) {
            if (db) |d| _ = c.sqlite3_close(d);
            return error.OpenFailed;
        }
        defer _ = c.sqlite3_close(db);
        if (c.sqlite3_exec(db, "CREATE TABLE huge (payload TEXT);", null, null, null) != c.SQLITE_OK) {
            return error.PopulateFailed;
        }

        var stmt: ?*c.sqlite3_stmt = null;
        if (c.sqlite3_prepare_v2(db, "INSERT INTO huge VALUES (?1)", -1, &stmt, null) != c.SQLITE_OK) {
            return error.PopulateFailed;
        }
        defer _ = c.sqlite3_finalize(stmt);

        const big = try allocator.alloc(u8, len);
        defer allocator.free(big);
        @memset(big, 'A');
        if (c.sqlite3_bind_text(stmt, 1, big.ptr, @intCast(big.len), SQLITE_STATIC) != c.SQLITE_OK) {
            return error.PopulateFailed;
        }
        if (c.sqlite3_step(stmt) != c.SQLITE_DONE) {
            return error.PopulateFailed;
        }
    }
};

test "sqlite_query: SELECT returns columns and rows as JSON" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"SELECT id, name FROM u WHERE id = 1\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"columns\":[\"id\",\"name\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[1,\"alice\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"row_count\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"truncated\":false") != null);
}

test "sqlite_query: WITH (CTE) allowed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs(
        \\{"db_path":"test.db","query":"WITH adults AS (SELECT * FROM u WHERE age >= 30) SELECT count(*) FROM adults"}
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[2]") != null);
}

test "sqlite_query: PRAGMA table_info allowed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"PRAGMA table_info(u)\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"name\"") != null);
}

test "sqlite_query: PRAGMA other than table_info rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"PRAGMA foreign_keys = ON\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "PRAGMA table_info") != null);
}

test "sqlite_query: rejects INSERT" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"INSERT INTO u (name) VALUES ('mallory')\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: rejects UPDATE" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"UPDATE u SET name='evil' WHERE id=1\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: rejects DROP" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"DROP TABLE u\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: rejects multi-statement (semicolon)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"SELECT 1; DROP TABLE u\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "multi-statement") != null);
}

test "sqlite_query: rejects ATTACH" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"ATTACH DATABASE 'other.db' AS other\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: respects max_rows cap (truncated=true)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/big.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populateMany(db_path_z.ptr, 50);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"big.db\",\"query\":\"SELECT id FROM big\",\"max_rows\":5}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"row_count\":5") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"truncated\":true") != null);
}

test "sqlite_query: redacts sensitive result values by default" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/sensitive.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populateSensitive(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"sensitive.db\",\"query\":\"SELECT email, card, api_token FROM sensitive\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "alice@example.com") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "4111 1111 1111 1111") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "sk-live-secret") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[EMAIL_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[CARD_1]") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[TOKEN_1]") != null);
}

test "sqlite_query: rejects SQL transforms that can bypass redaction" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/sensitive.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populateSensitive(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"sensitive.db\",\"query\":\"SELECT hex(email), substr(card, 1, 4) FROM sensitive\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);

    // Regression: output redaction cannot recover PII once SQL has encoded or
    // sliced it, so reject these transforms before SQLite prepares the query.
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "transform") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "616C696365406578616D706C652E636F6D") == null);
}

test "sqlite_query: include_sensitive is rejected in agent tool context" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/sensitive.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populateSensitive(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"sensitive.db\",\"query\":\"SELECT email, card, api_token FROM sensitive\",\"include_sensitive\":true}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "include_sensitive is not available") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "alice@example.com") == null);
}

test "sqlite_query: invalid db_path (traversal) rejected" {
    const allocator = std.testing.allocator;
    var sqt = SqliteQueryTool{ .workspace_dir = "/tmp/yc_test_sqlite_query_traversal" };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"../etc/passwd\",\"query\":\"SELECT 1\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "safety check") != null);
}

test "sqlite_query: invalid db_path (absolute) rejected" {
    const allocator = std.testing.allocator;
    var sqt = SqliteQueryTool{ .workspace_dir = "/tmp/yc_test_sqlite_query_abs" };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"/etc/passwd\",\"query\":\"SELECT 1\"}");
    defer parsed.deinit();
    const result = try t.execute(allocator, parsed.value.object);
    defer allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "safety check") != null);
}

test "sqlite_query: NULL column values render as JSON null" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"SELECT name FROM u WHERE id = 3\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[null]") != null);
}

test "sqlite_query: column name 'update_count' allowed (no false positive on UPDATE)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/aliased.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    {
        var db: ?*c.sqlite3 = null;
        _ = c.sqlite3_open(db_path_z.ptr, &db);
        defer _ = c.sqlite3_close(db);
        _ = c.sqlite3_exec(db, "CREATE TABLE m (update_count INTEGER); INSERT INTO m VALUES (42);", null, null, null);
    }

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs(
        \\{"db_path":"aliased.db","query":"SELECT update_count FROM m"}
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "[42]") != null);
}

test "sqlite_query: tool metadata sanity" {
    var sqt = SqliteQueryTool{ .workspace_dir = "/tmp" };
    const t = sqt.tool();
    try std.testing.expectEqualStrings("sqlite_query", t.name());
    try std.testing.expect(t.description().len > 0);
    try std.testing.expect(t.parametersJson().len > 0);
    try std.testing.expect(std.mem.indexOf(u8, t.parametersJson(), "db_path") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.parametersJson(), "query") != null);
    try std.testing.expect(std.mem.indexOf(u8, t.parametersJson(), "include_sensitive") == null);
}

test "classifyStatement: rejects empty" {
    try std.testing.expect(classifyStatement("") != null);
    try std.testing.expect(classifyStatement("   \t\n") != null);
}

test "classifyStatement: accepts SELECT" {
    try std.testing.expect(classifyStatement("SELECT 1") == null);
    try std.testing.expect(classifyStatement("  -- comment\nSELECT 1") == null);
    try std.testing.expect(classifyStatement("/* foo */ select * from t") == null);
    try std.testing.expect(classifyStatement("SELECT count(*) FROM t") == null);
    try std.testing.expect(classifyStatement("SELECT 'hex(email)' AS literal FROM t") == null);
}

test "classifyStatement: rejects keyword-prefixed garbage" {
    try std.testing.expect(classifyStatement("DROP TABLE x") != null);
    try std.testing.expect(classifyStatement("VACUUM") != null);
    try std.testing.expect(classifyStatement("CREATE TABLE x(a INT)") != null);
    try std.testing.expect(classifyStatement("BEGIN TRANSACTION") != null);
}

test "classifyStatement: rejects PRAGMA look-alikes" {
    // Forward-compatibility paranoia: only the exact `table_info` pragma is
    // allowed. Look-alike names (different keyword OR table_info with extra
    // alphanumeric trailing chars) must be rejected.
    try std.testing.expect(classifyStatement("PRAGMA foreign_keys = ON") != null);
    try std.testing.expect(classifyStatement("PRAGMA table_infox") != null); // longer keyword
    try std.testing.expect(classifyStatement("PRAGMA writable_schema = 1") != null);
    // `PRAGMA table_info` standalone (no parens) is OK — sqlite still parses
    // it as the table_info pragma form (returns empty result without arg).
    try std.testing.expect(classifyStatement("PRAGMA table_info") == null);
    try std.testing.expect(classifyStatement("PRAGMA table_info(u)") == null);
    try std.testing.expect(classifyStatement("PRAGMA table_info ( u )") == null);
}

test "classifyStatement: rejects redaction-bypass transforms" {
    try std.testing.expect(classifyStatement("SELECT hex(email) FROM sensitive") != null);
    try std.testing.expect(classifyStatement("SELECT quote(api_token) FROM sensitive") != null);
    try std.testing.expect(classifyStatement("SELECT substr(email, 1, 4) FROM sensitive") != null);
    try std.testing.expect(classifyStatement("WITH s AS (SELECT email FROM sensitive) SELECT upper(email) FROM s") != null);
}

test "sqlite_query: max_rows <= 0 explicitly rejected" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs(
        \\{"db_path":"test.db","query":"SELECT 1","max_rows":0}
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "max_rows must be >= 1") != null);
}

test "sqlite_query: max_bytes cap rolls back oversized row" {
    // Single fat TEXT cell larger than max_result_bytes — must be rolled back
    // and reported as truncated, not blow the cap.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/wide.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);

    {
        var db: ?*c.sqlite3 = null;
        _ = c.sqlite3_open(db_path_z.ptr, &db);
        defer _ = c.sqlite3_close(db);
        _ = c.sqlite3_exec(db, "CREATE TABLE w (payload TEXT);", null, null, null);
        // Build one ~10 KB row of 'A' chars + one short row.
        const big = try std.testing.allocator.alloc(u8, 10_000);
        defer std.testing.allocator.free(big);
        @memset(big, 'A');
        var sql_buf: [10_200]u8 = undefined;
        const sql = try std.fmt.bufPrintZ(&sql_buf, "INSERT INTO w VALUES ('{s}');", .{big});
        _ = c.sqlite3_exec(db, sql.ptr, null, null, null);
        _ = c.sqlite3_exec(db, "INSERT INTO w VALUES ('short');", null, null, null);
    }

    // Tool with tiny byte cap (1 KB). The 10 KB row must be rolled back.
    var sqt = SqliteQueryTool{
        .workspace_dir = ws_path,
        .max_result_bytes = 1024,
    };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"wide.db\",\"query\":\"SELECT payload FROM w\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    // First (10 KB) row rolled back → no rows surfaced; truncated=true.
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"truncated\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"row_count\":0") != null);
    // Output stays well under twice the cap (some JSON skeleton overhead is fine).
    try std.testing.expect(result.output.len < 2048);
}

test "sqlite_query: huge text and aliases stay within max_result_bytes" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/huge.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populateHugeText(db_path_z.ptr, std.testing.allocator, 100_000);

    const alias = try std.testing.allocator.alloc(u8, 2048);
    defer std.testing.allocator.free(alias);
    @memset(alias, 'A');
    const query = try std.fmt.allocPrint(std.testing.allocator, "SELECT payload AS '{s}' FROM huge", .{alias});
    defer std.testing.allocator.free(query);
    const args_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"db_path\":\"huge.db\",\"query\":\"{s}\"}}", .{query});
    defer std.testing.allocator.free(args_json);

    var sqt = SqliteQueryTool{
        .workspace_dir = ws_path,
        .max_result_bytes = 512,
    };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs(args_json);
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(result.output.len <= 512);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"truncated\":true") != null);
}

test "sqlite_query: redacted output stays within max_result_bytes" {
    // Regression: short sensitive values can expand during redaction, so the
    // final returned payload must still obey max_result_bytes.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/emails.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);

    {
        var db: ?*c.sqlite3 = null;
        if (c.sqlite3_open(db_path_z.ptr, &db) != c.SQLITE_OK) return error.OpenFailed;
        defer _ = c.sqlite3_close(db);

        if (c.sqlite3_exec(db, "CREATE TABLE emails (email TEXT);", null, null, null) != c.SQLITE_OK) {
            return error.PopulateFailed;
        }
        var i: usize = 0;
        while (i < 40) : (i += 1) {
            if (c.sqlite3_exec(db, "INSERT INTO emails VALUES ('a@b.co');", null, null, null) != c.SQLITE_OK) {
                return error.PopulateFailed;
            }
        }
    }

    var sqt = SqliteQueryTool{
        .workspace_dir = ws_path,
        .max_result_bytes = 512,
    };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"emails.db\",\"query\":\"SELECT email FROM emails\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);

    try std.testing.expect(result.success);
    try std.testing.expect(result.output.len <= 512);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "a@b.co") == null);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"truncated\":true") != null);
}

// ════════════════════════════════════════════════════════════════════════════
// Negative security tests
// ════════════════════════════════════════════════════════════════════════════

test "sqlite_query: rejects DELETE" {
    // Regression: parallel coverage to INSERT/UPDATE/DROP via the execute path,
    // not just the classifier unit test. Locks the tool surface.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"DELETE FROM u WHERE id=1\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: rejects CREATE TABLE via execute" {
    // Regression: classifier rejects CREATE in unit tests; this locks the same
    // behavior at the public tool surface.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"CREATE TABLE evil (x INT)\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: lowercase write keywords rejected" {
    // Regression: case-insensitivity must hold at the tool surface, not only
    // in classifier unit tests. `delete from ...` would slip through a naive
    // case-sensitive matcher.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"delete from u where id=1\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: comment-prefixed write rejected" {
    // Regression: a leading SQL comment must not let an attacker hide a write
    // statement from the classifier (`-- innocent\nDROP TABLE u`).
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs(
        "{\"db_path\":\"test.db\",\"query\":\"-- innocent looking comment\\nDROP TABLE u\"}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: block-comment-prefixed write rejected" {
    // Regression: same as above but with `/* ... */` block comments.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs(
        "{\"db_path\":\"test.db\",\"query\":\"/* SELECT-ish */ INSERT INTO u (name) VALUES ('mallory')\"}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
}

test "sqlite_query: empty query rejected via execute" {
    // Regression: classifier rejects empty/whitespace-only input; verify the
    // failure surfaces through the public tool API too.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"test.db\",\"query\":\"   \\n\\t  \"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "empty query") != null);
}

test "sqlite_query: db_path with embedded null byte rejected" {
    // Regression: a null byte must not survive path_security.isPathSafe and
    // reach sqlite3_open. JsonObjectMap is built directly to avoid relying on
    // std.json's handling of `\u0000` escapes.
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var obj: JsonObjectMap = .empty;
    try obj.put(arena_alloc, "db_path", .{ .string = "safe\x00.db" });
    try obj.put(arena_alloc, "query", .{ .string = "SELECT 1" });

    var sqt = SqliteQueryTool{ .workspace_dir = "/tmp/yc_test_sqlite_query_nul" };
    const t = sqt.tool();
    const result = try t.execute(allocator, obj);
    defer allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "safety check") != null);
}

test "sqlite_query: max_rows of wrong JSON type ignored, defaults applied" {
    // Regression: if a model passes `"max_rows":"100"` (string), getInt returns
    // null and the tool must fall back to its configured default rather than
    // crashing or running unbounded.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);
    const db_path_z = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/test.db", .{ws_path}, 0);
    defer std.testing.allocator.free(db_path_z);
    try TestDb.populate(db_path_z.ptr);

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path, .max_result_rows = 10 };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs(
        "{\"db_path\":\"test.db\",\"query\":\"SELECT id FROM u\",\"max_rows\":\"100\"}",
    );
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "\"row_count\":3") != null);
}

test "sqlite_query: symlink escape (db_path → outside workspace) rejected" {
    // Defense via realpath + isResolvedPathAllowed: a workspace-relative
    // symlink that points outside the workspace must not let the agent read
    // arbitrary files. If a future refactor drops the realpath step, this
    // test fires.
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const ws_path = try @import("compat").fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(ws_path);

    // Create a real DB outside the workspace so realpath actually resolves.
    var outside_tmp = std.testing.tmpDir(.{});
    defer outside_tmp.cleanup();
    const outside_path = try @import("compat").fs.Dir.wrap(outside_tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(outside_path);
    const outside_db = try std.fmt.allocPrintSentinel(std.testing.allocator, "{s}/secret.db", .{outside_path}, 0);
    defer std.testing.allocator.free(outside_db);
    try TestDb.populate(outside_db.ptr);

    // Symlink workspace/escape.db → outside/secret.db (using compat Dir API)
    @import("compat").fs.Dir.wrap(tmp.dir).symLink(outside_db, "escape.db", .{}) catch |err| {
        // If symlink creation fails (e.g. unsupported FS), skip the test.
        std.log.warn("symlink unsupported on this filesystem: {s}", .{@errorName(err)});
        return error.SkipZigTest;
    };

    var sqt = SqliteQueryTool{ .workspace_dir = ws_path };
    const t = sqt.tool();
    const parsed = try root.parseTestArgs("{\"db_path\":\"escape.db\",\"query\":\"SELECT 1\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer std.testing.allocator.free(result.output);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "outside workspace") != null);
}
