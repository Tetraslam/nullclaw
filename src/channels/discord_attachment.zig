//! Shared Discord attachment parsing, durable paths, receipts, and downloads.

const std = @import("std");
const std_compat = @import("compat");
const multimodal = @import("../multimodal.zig");

pub const MAX_ATTACHMENT_BYTES: u64 = 50 * 1024 * 1024;
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 10;
pub const MAX_RECEIPT_BYTES: usize = 8192;
const READY_MARKER = ".ready";
const PUBLISHED_MARKER = ".published";

pub const Attachment = struct {
    id: []const u8,
    filename: []const u8,
    size: u64,
    content_type: ?[]const u8,
    url: []const u8,
    proxy_url: ?[]const u8,
    width: ?u64,
    height: ?u64,
};

pub const DownloadFn = *const fn (?*anyopaque, std.mem.Allocator, []const u8, *std_compat.fs.File, u64) anyerror!u64;

pub const MessageStore = struct {
    allocator: std.mem.Allocator,
    parent: std_compat.fs.Dir,
    dir: std_compat.fs.Dir,
    path: []u8,
    message_id: []const u8,
    created: bool,
    writable: bool,
    needs_commit: bool,
    dir_open: bool = true,

    pub fn deinit(self: *MessageStore) void {
        if (self.dir_open) self.dir.close();
        self.parent.close();
        self.allocator.free(self.path);
    }

    pub fn cleanupCreated(self: *MessageStore) !void {
        if (!self.created) return;
        if (self.dir_open) {
            self.dir.close();
            self.dir_open = false;
        }
        try self.parent.deleteTree(self.message_id);
        self.created = false;
    }

    pub fn prepare(self: *MessageStore) !void {
        if (!self.writable) return;
        const marker = try self.dir.createFile(READY_MARKER, .{
            .read = true,
            .exclusive = true,
            .permissions = std_compat.fs.permissionsFromMode(0o600),
            .resolve_beneath = true,
        });
        defer marker.close();
        try marker.sync();
    }

    pub fn commitPublished(self: *MessageStore) !void {
        if (!self.needs_commit) return;
        try self.dir.rename(READY_MARKER, PUBLISHED_MARKER);
        self.needs_commit = false;
    }
};

fn objectString(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return null;
    return value.string;
}

fn optionalUnsigned(object: std.json.ObjectMap, key: []const u8) !?u64 {
    const value = object.get(key) orelse return null;
    if (value == .null) return null;
    if (value != .integer or value.integer < 0) return error.InvalidAttachment;
    return @intCast(value.integer);
}

fn validSnowflake(value: []const u8) bool {
    if (value.len == 0 or value.len > 32) return false;
    for (value) |ch| if (!std.ascii.isDigit(ch)) return false;
    return true;
}

fn safeReceiptToken(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |ch| if (ch < 0x20 or ch == 0x7f or ch == ';' or ch == '[' or ch == ']') return false;
    return true;
}

pub fn isAllowedUrl(url: []const u8) bool {
    const scheme = "https://";
    if (url.len <= scheme.len or !std.ascii.startsWithIgnoreCase(url, scheme)) return false;
    const remainder = url[scheme.len..];
    const slash = std.mem.indexOfScalar(u8, remainder, '/') orelse return false;
    const host = remainder[0..slash];
    return std.ascii.eqlIgnoreCase(host, "cdn.discordapp.com") or
        std.ascii.eqlIgnoreCase(host, "media.discordapp.net");
}

pub fn parse(object: std.json.ObjectMap) !Attachment {
    const id = objectString(object, "id") orelse return error.InvalidAttachment;
    if (!validSnowflake(id)) return error.InvalidAttachment;
    const filename = objectString(object, "filename") orelse return error.InvalidAttachment;
    const size = (try optionalUnsigned(object, "size")) orelse return error.InvalidAttachment;
    const url = objectString(object, "url") orelse return error.InvalidAttachment;
    if (!isAllowedUrl(url)) return error.InvalidAttachmentUrl;
    const proxy_url = objectString(object, "proxy_url");
    if (proxy_url) |proxy| if (!isAllowedUrl(proxy)) return error.InvalidAttachmentUrl;
    const content_type = objectString(object, "content_type");
    if (content_type) |mime| if (!safeReceiptToken(mime)) return error.InvalidAttachment;
    return .{
        .id = id,
        .filename = filename,
        .size = size,
        .content_type = content_type,
        .url = url,
        .proxy_url = proxy_url,
        .width = try optionalUnsigned(object, "width"),
        .height = try optionalUnsigned(object, "height"),
    };
}

pub fn sanitizeFilename(allocator: std.mem.Allocator, filename: []const u8) ![]u8 {
    const base = std_compat.fs.path.basename(filename);
    const source = if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) "attachment" else base;
    const capped = source[0..@min(source.len, 180)];
    const out = try allocator.dupe(u8, capped);
    for (out) |*ch| {
        if (ch.* < 0x20 or ch.* == 0x7f or ch.* == '/' or ch.* == '\\' or ch.* == ':' or ch.* == ';' or ch.* == '[' or ch.* == ']') ch.* = '_';
    }
    return out;
}

pub fn messageDir(allocator: std.mem.Allocator, workspace_dir: []const u8, channel_id: []const u8, message_id: []const u8) ![]u8 {
    if (!std.fs.path.isAbsolute(workspace_dir) or !validSnowflake(channel_id) or !validSnowflake(message_id)) return error.InvalidAttachmentPath;
    return std_compat.fs.path.join(allocator, &.{ workspace_dir, "attachments", "discord", channel_id, message_id });
}

fn openChildDir(parent: std_compat.fs.Dir, name: []const u8, create: bool) !std_compat.fs.Dir {
    if (create) parent.makeDir(name) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |e| return e,
    };
    return parent.openDir(name, .{ .follow_symlinks = false });
}

fn hasMarker(dir: std_compat.fs.Dir, name: []const u8) bool {
    const marker = dir.openFile(name, .{
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch return false;
    defer marker.close();
    return (marker.stat() catch return false).kind == .file;
}

pub fn openMessageStore(
    allocator: std.mem.Allocator,
    workspace_dir: []const u8,
    channel_id: []const u8,
    message_id: []const u8,
    create: bool,
) !MessageStore {
    const path = try messageDir(allocator, workspace_dir, channel_id, message_id);
    errdefer allocator.free(path);

    var workspace = try std_compat.fs.openDirAbsolute(workspace_dir, .{ .follow_symlinks = false });
    defer workspace.close();
    var attachments = try openChildDir(workspace, "attachments", create);
    defer attachments.close();
    var discord = try openChildDir(attachments, "discord", create);
    defer discord.close();
    var channel = try openChildDir(discord, channel_id, create);
    errdefer channel.close();

    var created = false;
    var recovered_ready = false;
    if (create) {
        if (channel.makeDir(message_id)) |_| {
            created = true;
        } else |err| switch (err) {
            error.PathAlreadyExists => {
                var existing = channel.openDir(message_id, .{ .follow_symlinks = false }) catch return error.InvalidAttachmentPath;
                const published = hasMarker(existing, PUBLISHED_MARKER);
                const ready = hasMarker(existing, READY_MARKER);
                existing.close();
                if (ready and !published) {
                    recovered_ready = true;
                } else if (!published) {
                    try channel.deleteTree(message_id);
                    try channel.makeDir(message_id);
                    created = true;
                }
            },
            else => |e| return e,
        }
    }
    var dir = channel.openDir(message_id, .{ .follow_symlinks = false }) catch |err| {
        if (created) channel.deleteTree(message_id) catch return error.AttachmentCleanupFailed;
        return err;
    };
    errdefer dir.close();
    if (!create and !hasMarker(dir, PUBLISHED_MARKER)) return error.UnpublishedAttachmentStore;

    return .{
        .allocator = allocator,
        .parent = channel,
        .dir = dir,
        .path = path,
        .message_id = message_id,
        .created = created,
        .writable = created,
        .needs_commit = created or recovered_ready,
    };
}

pub fn attachmentPath(allocator: std.mem.Allocator, dir: []const u8, attachment: Attachment) ![]u8 {
    const leaf = try attachmentLeaf(allocator, attachment);
    defer allocator.free(leaf);
    return std_compat.fs.path.join(allocator, &.{ dir, leaf });
}

pub fn attachmentLeaf(allocator: std.mem.Allocator, attachment: Attachment) ![]u8 {
    const safe = try sanitizeFilename(allocator, attachment.filename);
    defer allocator.free(safe);
    return std.fmt.allocPrint(allocator, "{s}-{s}", .{ attachment.id, safe });
}

pub fn detectFileMime(file: std_compat.fs.File) ?[]const u8 {
    file.seekTo(0) catch return null;
    var header: [16]u8 = undefined;
    const count = file.read(&header) catch return null;
    file.seekTo(0) catch return null;
    const bytes = header[0..count];
    if (multimodal.detectMimeType(bytes)) |mime| return mime;
    if (std.mem.startsWith(u8, bytes, "%PDF-")) return "application/pdf";
    return null;
}

fn isSupportedImageMime(mime: []const u8) bool {
    return std.mem.eql(u8, mime, "image/png") or
        std.mem.eql(u8, mime, "image/jpeg") or
        std.mem.eql(u8, mime, "image/webp") or
        std.mem.eql(u8, mime, "image/gif") or
        std.mem.eql(u8, mime, "image/bmp");
}

pub fn appendReceipt(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    attachment: Attachment,
    sanitized_name: []const u8,
    message_id: []const u8,
    path: ?[]const u8,
    actual_bytes: ?u64,
    actual_mime: ?[]const u8,
    failure: ?[]const u8,
) !void {
    const receipt_start = out.items.len;
    var aw: std.Io.Writer.Allocating = .fromArrayList(allocator, out);
    const w = &aw.writer;
    if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try w.writeByte('\n');
    try w.print("[Discord attachment: name={s}; declared_mime={s}; declared_bytes={d}; message_id={s}; attachment_id={s}", .{
        sanitized_name,
        attachment.content_type orelse "unknown",
        attachment.size,
        if (validSnowflake(message_id)) message_id else "unknown",
        attachment.id,
    });
    if (attachment.width) |width| try w.print("; width={d}", .{width});
    if (attachment.height) |height| try w.print("; height={d}", .{height});
    if (actual_mime) |mime| try w.print("; actual_mime={s}", .{mime});
    if (actual_bytes) |bytes| try w.print("; bytes={d}", .{bytes});
    if (path) |stored| try w.print("; path={s}", .{stored});
    if (failure) |reason| try w.print("; status=failed; reason={s}", .{reason}) else try w.writeAll("; status=stored");
    try w.writeAll("]");
    if (failure == null and actual_mime != null and path != null and isSupportedImageMime(actual_mime.?)) try w.print("\n[IMAGE:{s}]", .{path.?});
    out.* = aw.toArrayList();
    if (out.items.len - receipt_start > MAX_RECEIPT_BYTES) return error.ReceiptTooLarge;
}

pub fn appendInvalidReceipt(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    object: ?std.json.ObjectMap,
    message_id: []const u8,
    reason: []const u8,
) !void {
    const receipt_start = out.items.len;
    const filename = if (object) |value| objectString(value, "filename") orelse "unknown" else "unknown";
    const safe = try sanitizeFilename(allocator, filename);
    defer allocator.free(safe);
    const raw_attachment_id = if (object) |value| objectString(value, "id") orelse "unknown" else "unknown";
    const attachment_id = if (validSnowflake(raw_attachment_id)) raw_attachment_id else "unknown";
    const raw_declared_mime = if (object) |value| objectString(value, "content_type") orelse "unknown" else "unknown";
    const declared_mime = if (safeReceiptToken(raw_declared_mime)) raw_declared_mime else "unknown";
    const declared_size = if (object) |value| optionalUnsigned(value, "size") catch null else null;
    var aw: std.Io.Writer.Allocating = .fromArrayList(allocator, out);
    const w = &aw.writer;
    if (out.items.len > 0 and out.items[out.items.len - 1] != '\n') try w.writeByte('\n');
    try w.print("[Discord attachment: name={s}; declared_mime={s}; declared_bytes=", .{ safe, declared_mime });
    if (declared_size) |size| try w.print("{d}", .{size}) else try w.writeAll("unknown");
    try w.print("; message_id={s}; attachment_id={s}; status=failed; reason={s}]", .{
        if (validSnowflake(message_id)) message_id else "unknown",
        attachment_id,
        reason,
    });
    out.* = aw.toArrayList();
    if (out.items.len - receipt_start > MAX_RECEIPT_BYTES) return error.ReceiptTooLarge;
}

pub fn appendStoredReceipt(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    store: *MessageStore,
    attachment: Attachment,
    safe_name: []const u8,
) !void {
    const leaf = try attachmentLeaf(allocator, attachment);
    defer allocator.free(leaf);
    const path = try std_compat.fs.path.join(allocator, &.{ store.path, leaf });
    defer allocator.free(path);
    const file = store.dir.openFile(leaf, .{
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch {
        try appendReceipt(out, allocator, attachment, safe_name, store.message_id, null, null, null, "NotStoredLocally");
        return;
    };
    defer file.close();
    const stat = file.stat() catch |err| {
        try appendReceipt(out, allocator, attachment, safe_name, store.message_id, null, null, null, @errorName(err));
        return;
    };
    if (stat.kind != .file) {
        try appendReceipt(out, allocator, attachment, safe_name, store.message_id, null, null, null, "StoredPathNotFile");
    } else if (stat.size > MAX_ATTACHMENT_BYTES) {
        try appendReceipt(out, allocator, attachment, safe_name, store.message_id, null, null, null, "StoredFileExceedsLimit");
    } else {
        try appendReceipt(out, allocator, attachment, safe_name, store.message_id, path, stat.size, detectFileMime(file), null);
    }
}

pub fn appendHistoryReceipts(
    out: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    attachments: std.json.Value,
    workspace_dir: []const u8,
    channel_id: []const u8,
    message_id: []const u8,
) !void {
    if (attachments != .array) {
        try appendInvalidReceipt(out, allocator, null, message_id, "AttachmentsNotArray");
        return;
    }
    var store = openMessageStore(allocator, workspace_dir, channel_id, message_id, false) catch null;
    defer if (store) |*value| value.deinit();
    const count = @min(attachments.array.items.len, MAX_ATTACHMENTS_PER_MESSAGE);
    for (attachments.array.items[0..count]) |item| {
        const object = if (item == .object) item.object else null;
        const attachment = if (object) |value| parse(value) catch |err| {
            try appendInvalidReceipt(out, allocator, value, message_id, @errorName(err));
            continue;
        } else {
            try appendInvalidReceipt(out, allocator, null, message_id, "InvalidAttachment");
            continue;
        };
        const safe = try sanitizeFilename(allocator, attachment.filename);
        defer allocator.free(safe);
        if (attachment.size > MAX_ATTACHMENT_BYTES) {
            try appendReceipt(out, allocator, attachment, safe, message_id, null, null, null, "DeclaredSizeExceedsLimit");
            continue;
        }
        if (store == null) {
            try appendReceipt(out, allocator, attachment, safe, message_id, null, null, null, "NotStoredLocally");
            continue;
        }
        try appendStoredReceipt(out, allocator, &store.?, attachment, safe);
    }
    if (attachments.array.items.len > count)
        try appendInvalidReceipt(out, allocator, null, message_id, "TooManyAttachments");
}

fn stopChild(child: *std_compat.process.Child) void {
    _ = child.kill() catch {};
    _ = child.wait() catch {};
}

pub fn curlDownload(_: ?*anyopaque, allocator: std.mem.Allocator, url: []const u8, file: *std_compat.fs.File, max_bytes: u64) !u64 {
    if (!isAllowedUrl(url)) return error.InvalidAttachmentUrl;
    const max_text = try std.fmt.allocPrint(allocator, "{d}", .{max_bytes});
    defer allocator.free(max_text);
    var argv = [_][]const u8{
        "curl",    "--silent", "--show-error",  "--fail", "--location", "--max-redirs", "0",
        "--proto", "=https",   "--proto-redir", "=https", "--max-time", "120",          "--max-filesize",
        max_text,  url,
    };
    var child = std_compat.process.Child.init(&argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    var total: u64 = 0;
    var buffer: [64 * 1024]u8 = undefined;
    while (true) {
        const read_count = child.stdout.?.read(&buffer) catch {
            stopChild(&child);
            return error.DownloadFailed;
        };
        if (read_count == 0) break;
        if (read_count > max_bytes - total) {
            stopChild(&child);
            return error.AttachmentTooLarge;
        }
        file.writeAll(buffer[0..read_count]) catch |err| {
            stopChild(&child);
            return err;
        };
        total += read_count;
    }
    const term = child.wait() catch {
        stopChild(&child);
        return error.DownloadFailed;
    };
    if (term != .exited or term.exited != 0) return error.DownloadFailed;
    try file.sync();
    return total;
}

test "discord attachment parses retained metadata and validates CDN" {
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator,
        \\{"id":"123","filename":"image.png","size":7126536,"content_type":"image/png","url":"https://cdn.discordapp.com/attachments/1/2/image.png","proxy_url":"https://media.discordapp.net/attachments/1/2/image.png","width":3000,"height":4000}
    , .{});
    defer parsed.deinit();
    const attachment = try parse(parsed.value.object);
    try std.testing.expectEqual(@as(u64, 7126536), attachment.size);
    try std.testing.expectEqual(@as(?u64, 3000), attachment.width);
    try std.testing.expect(!isAllowedUrl("https://example.com/image.png"));
}

test "discord attachment sanitizes traversal filename" {
    const safe = try sanitizeFilename(std.testing.allocator, "../../evil.png");
    defer std.testing.allocator.free(safe);
    try std.testing.expectEqualStrings("evil.png", safe);
}

test "discord attachment store rejects symlink components" {
    if (@import("builtin").os.tag == .windows) return;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);
    try std_compat.fs.Dir.wrap(tmp.dir).makeDir("outside");
    try std_compat.fs.Dir.wrap(tmp.dir).symLink("outside", "attachments", .{ .is_directory = true });
    if (openMessageStore(std.testing.allocator, workspace, "100", "200", true)) |store_value| {
        var store = store_value;
        store.deinit();
        return error.TestUnexpectedResult;
    } else |_| {}
}

test "discord attachment store replaces an interrupted unsealed directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);
    var first = try openMessageStore(std.testing.allocator, workspace, "100", "200", true);
    const stale = try first.dir.createFile("stale", .{});
    stale.close();
    first.deinit();

    var recovered = try openMessageStore(std.testing.allocator, workspace, "100", "200", true);
    defer recovered.deinit();
    try std.testing.expect(recovered.created);
    try std.testing.expectError(error.FileNotFound, recovered.dir.access("stale", .{}));
}

test "discord attachment store preserves complete ready directory for replay" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const workspace = try std_compat.fs.Dir.wrap(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(workspace);
    var first = try openMessageStore(std.testing.allocator, workspace, "100", "200", true);
    const retained = try first.dir.createFile("retained", .{});
    retained.close();
    try first.prepare();
    first.deinit();

    var recovered = try openMessageStore(std.testing.allocator, workspace, "100", "200", true);
    defer recovered.deinit();
    try std.testing.expect(!recovered.created);
    try std.testing.expect(!recovered.writable);
    try std.testing.expect(recovered.needs_commit);
    try recovered.dir.access("retained", .{});
    try recovered.commitPublished();
}
