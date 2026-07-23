//! Discord REST helpers for hydrating session history.
//!
//! Separate from the gateway websocket: these call discord.com/api/v10 over
//! plain HTTPS with the bot token, used to (a) resolve a recipient user id to
//! their DM channel id, and (b) pull recent messages from a channel so a cold
//! session can resume with context instead of amnesia.

const std = @import("std");
const http_util = @import("../http_util.zig");

const Allocator = std.mem.Allocator;
const log = std.log.scoped(.discord_history);

pub const HistoryMessage = struct {
    /// "user" or "assistant" (from the bot).
    role: []const u8,
    content: []const u8,
    /// Snowflake id string, used for dedup against persisted history.
    id: []const u8,
    /// Author user id (snowflake), for role remapping by the caller.
    author_id: []const u8,
    /// Best available Discord display name for shared-channel transcripts.
    author_name: []const u8,
    is_bot: bool,
};

fn authHeader(allocator: Allocator, token: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "Authorization: Bot {s}", .{token});
}

fn apiGet(allocator: Allocator, token: []const u8, url: []const u8) ![]u8 {
    const auth = try authHeader(allocator, token);
    defer allocator.free(auth);
    return http_util.httpGetWithProxy(allocator, url, &.{auth}, null);
}

fn apiPost(allocator: Allocator, token: []const u8, url: []const u8, body: []const u8) ![]u8 {
    const auth = try authHeader(allocator, token);
    defer allocator.free(auth);
    return http_util.httpPostJsonWithProxy(allocator, url, body, &.{auth}, null);
}

fn memberAuthorName(
    allocator: Allocator,
    message: std.json.ObjectMap,
    author: std.json.ObjectMap,
    author_id: []const u8,
) ![]u8 {
    const username = if (author.get("username")) |value|
        if (value == .string and value.string.len > 0) value.string else author_id
    else
        author_id;
    const global_name = if (author.get("global_name")) |value|
        if (value == .string and value.string.len > 0) value.string else username
    else
        username;
    const nickname = if (message.get("member")) |member_value|
        if (member_value == .object) blk: {
            const value = member_value.object.get("nick") orelse break :blk null;
            break :blk if (value == .string and value.string.len > 0) value.string else null;
        } else null
    else
        null;
    const display_name = nickname orelse global_name;
    if (!std.mem.eql(u8, display_name, username)) {
        return std.fmt.allocPrint(allocator, "{s} (@{s})", .{ display_name, username });
    }
    return allocator.dupe(u8, username);
}

/// Resolve a recipient user id to their DM channel id via
/// POST /users/@me/channels. Caller frees the returned slice.
pub fn resolveDmChannelId(allocator: Allocator, token: []const u8, user_id: []const u8) ![]u8 {
    const url = "https://discord.com/api/v10/users/@me/channels";
    const body = try std.fmt.allocPrint(allocator, "{{\"recipient_id\":\"{s}\"}}", .{user_id});
    defer allocator.free(body);

    const resp = try apiPost(allocator, token, url, body);
    defer allocator.free(resp);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.DiscordUnexpectedResponse;
    const id_val = parsed.value.object.get("id") orelse return error.DiscordNoChannel;
    return switch (id_val) {
        .string => |s| try allocator.dupe(u8, s),
        else => error.DiscordNoChannel,
    };
}

/// Fetch up to `limit` most-recent messages from a channel, oldest-first.
/// Returns messages in chronological order with roles mapped (bot -> assistant).
/// Caller owns the slice and each message's fields (all duped on `allocator`).
pub fn fetchChannelHistory(
    allocator: Allocator,
    token: []const u8,
    channel_id: []const u8,
    limit: u32,
    bot_user_id: []const u8,
) ![]HistoryMessage {
    const url = try std.fmt.allocPrint(
        allocator,
        "https://discord.com/api/v10/channels/{s}/messages?limit={d}",
        .{ channel_id, @min(limit, 100) },
    );
    defer allocator.free(url);

    const resp = try apiGet(allocator, token, url);
    defer allocator.free(resp);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, resp, .{});
    defer parsed.deinit();
    if (parsed.value != .array) return error.DiscordUnexpectedResponse;

    const items = parsed.value.array.items;
    var out: std.ArrayListUnmanaged(HistoryMessage) = .empty;
    errdefer {
        for (out.items) |m| {
            allocator.free(m.role);
            allocator.free(m.content);
            allocator.free(m.id);
            allocator.free(m.author_id);
            allocator.free(m.author_name);
        }
        out.deinit(allocator);
    }

    // API returns newest-first; walk backward for chronological order.
    var i: usize = items.len;
    while (i > 0) {
        i -= 1;
        const item = items[i];
        if (item != .object) continue;
        const obj = item.object;

        const id: []const u8 = switch (obj.get("id") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        // Skip non-user messages (system, joins, etc.) — they carry no author content.
        const msg_type: i64 = switch (obj.get("type") orelse std.json.Value{ .integer = 0 }) {
            .integer => |t| t,
            else => 0,
        };
        if (msg_type != 0 and msg_type != 19) continue; // default + reply only

        const content: []const u8 = switch (obj.get("content") orelse std.json.Value{ .string = "" }) {
            .string => |s| s,
            else => "",
        };
        if (content.len == 0) continue;

        const author = obj.get("author") orelse continue;
        if (author != .object) continue;
        const author_id: []const u8 = switch (author.object.get("id") orelse continue) {
            .string => |s| s,
            else => continue,
        };

        const author_name = try memberAuthorName(allocator, obj, author.object, author_id);
        defer allocator.free(author_name);

        const is_bot = if (bot_user_id.len > 0)
            std.mem.eql(u8, author_id, bot_user_id)
        else if (author.object.get("bot")) |bot|
            bot == .bool and bot.bool
        else
            false;
        const role: []const u8 = if (is_bot) "assistant" else "user";

        try out.append(allocator, .{
            .role = try allocator.dupe(u8, role),
            .content = try allocator.dupe(u8, content),
            .id = try allocator.dupe(u8, id),
            .author_id = try allocator.dupe(u8, author_id),
            .author_name = try allocator.dupe(u8, author_name),
            .is_bot = is_bot,
        });
    }

    return out.toOwnedSlice(allocator);
}

/// Rough token estimate for a block of text (chars/4, the usual heuristic).
pub fn estimateTokens(text: []const u8) u64 {
    return @intCast(@max(1, text.len / 4));
}

test "estimateTokens" {
    try std.testing.expectEqual(@as(u64, 1), estimateTokens("hi"));
    try std.testing.expectEqual(@as(u64, 25), estimateTokens("a" ** 100));
}

test "memberAuthorName includes server nickname and username" {
    const allocator = std.testing.allocator;
    const parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        "{\"author\":{\"id\":\"1\",\"username\":\"lucas\",\"global_name\":\"Lucas\"},\"member\":{\"nick\":\"Prime\"}}",
        .{},
    );
    defer parsed.deinit();
    const message = parsed.value.object;
    const name = try memberAuthorName(allocator, message, message.get("author").?.object, "1");
    defer allocator.free(name);
    try std.testing.expectEqualStrings("Prime (@lucas)", name);
}
