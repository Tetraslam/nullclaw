const std = @import("std");
const std_compat = @import("compat");

fn boundaryDir(allocator: std.mem.Allocator, workspace_dir: []const u8) ![]u8 {
    return std_compat.fs.path.join(allocator, &.{ workspace_dir, ".thread-boundaries" });
}

fn boundaryPath(allocator: std.mem.Allocator, workspace_dir: []const u8, session_key: []const u8) ![]u8 {
    const hash = std.hash.Wyhash.hash(0, session_key);
    const dir = try boundaryDir(allocator, workspace_dir);
    defer allocator.free(dir);
    const name = try std.fmt.allocPrint(allocator, "{x}.txt", .{hash});
    defer allocator.free(name);
    return std_compat.fs.path.join(allocator, &.{ dir, name });
}

pub fn save(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    session_key: []const u8,
    message_id: []const u8,
) !void {
    const dir = try boundaryDir(allocator, workspace_dir);
    defer allocator.free(dir);
    std_compat.fs.makeDirAbsolute(dir) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    const path = try boundaryPath(allocator, workspace_dir, session_key);
    defer allocator.free(path);
    const file = try std_compat.fs.createFileAbsolute(path, .{ .truncate = true, .read = false });
    defer file.close();
    try file.writeAll(message_id);
}

pub fn load(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    session_key: []const u8,
) ?[]u8 {
    const path = boundaryPath(allocator, workspace_dir, session_key) catch return null;
    defer allocator.free(path);
    const file = std_compat.fs.openFileAbsolute(path, .{}) catch return null;
    defer file.close();
    const raw = file.readToEndAlloc(allocator, 128) catch return null;
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) {
        allocator.free(raw);
        return null;
    }
    if (trimmed.ptr == raw.ptr and trimmed.len == raw.len) return raw;
    const result = allocator.dupe(u8, trimmed) catch {
        allocator.free(raw);
        return null;
    };
    allocator.free(raw);
    return result;
}

test "thread boundary save and load" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);

    try save(std.testing.allocator, workspace, "agent:main:discord:channel:42", "123456");
    const loaded = load(std.testing.allocator, workspace, "agent:main:discord:channel:42") orelse
        return error.TestUnexpectedResult;
    defer std.testing.allocator.free(loaded);
    try std.testing.expectEqualStrings("123456", loaded);
}
