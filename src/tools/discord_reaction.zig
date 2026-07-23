//! Add or remove the bot's reaction in the current Discord channel.

const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const http_util = @import("../http_util.zig");
const url_percent = @import("../url_percent.zig");

const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

threadlocal var turn_account_id: ?[]const u8 = null;
threadlocal var turn_channel_id: ?[]const u8 = null;
threadlocal var turn_message_id: ?[]const u8 = null;

pub const DiscordReactionTool = struct {
    accounts: []const config_types.DiscordConfig = &.{},

    pub const tool_name = "discord_reaction";
    pub const tool_description = "Add or remove your reaction on a message in the current Discord channel. Omit message_id to react to the message that triggered this turn.";
    pub const tool_params =
        \\{"type":"object","properties":{"emoji":{"type":"string","minLength":1,"description":"Unicode emoji or custom Discord emoji in name:id form"},"message_id":{"type":"string","description":"Message ID in the current channel; defaults to the triggering message"},"action":{"type":"string","enum":["add","remove"],"default":"add"}},"required":["emoji"]}
    ;

    pub const TurnContext = struct {
        account_id: ?[]const u8,
        channel_id: ?[]const u8,
        message_id: ?[]const u8,
    };

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *DiscordReactionTool) Tool {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn setContext(
        _: *DiscordReactionTool,
        account_id: ?[]const u8,
        channel_id: ?[]const u8,
        message_id: ?[]const u8,
    ) TurnContext {
        const previous = TurnContext{
            .account_id = turn_account_id,
            .channel_id = turn_channel_id,
            .message_id = turn_message_id,
        };
        turn_account_id = account_id;
        turn_channel_id = channel_id;
        turn_message_id = message_id;
        return previous;
    }

    pub fn restoreContext(previous: TurnContext) void {
        turn_account_id = previous.account_id;
        turn_channel_id = previous.channel_id;
        turn_message_id = previous.message_id;
    }

    fn currentAccount(self: *const DiscordReactionTool) ?config_types.DiscordConfig {
        const account_id = turn_account_id orelse return null;
        for (self.accounts) |candidate| {
            if (std.mem.eql(u8, candidate.account_id, account_id)) return candidate;
        }
        return null;
    }

    fn isSnowflake(value: []const u8) bool {
        if (value.len == 0 or value.len > 20) return false;
        for (value) |byte| if (!std.ascii.isDigit(byte)) return false;
        return true;
    }

    fn normalizeEmoji(raw: []const u8) []const u8 {
        const emoji = std.mem.trim(u8, raw, " \t\r\n");
        if (emoji.len >= 4 and emoji[0] == '<' and emoji[emoji.len - 1] == '>') {
            if (std.mem.startsWith(u8, emoji, "<:")) return emoji[2 .. emoji.len - 1];
            if (std.mem.startsWith(u8, emoji, "<a:")) return emoji[3 .. emoji.len - 1];
        }
        return emoji;
    }

    pub fn execute(self: *DiscordReactionTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        const channel_id = turn_channel_id orelse return ToolResult.fail("No Discord channel is associated with this conversation");
        if (!isSnowflake(channel_id)) return ToolResult.fail("The current Discord channel ID is invalid");
        const message_id = root.getString(args, "message_id") orelse turn_message_id orelse
            return ToolResult.fail("No Discord message is associated with this turn");
        if (!isSnowflake(message_id)) return ToolResult.fail("The Discord message ID is invalid");
        const emoji = normalizeEmoji(root.getString(args, "emoji") orelse return ToolResult.fail("emoji is required"));
        if (emoji.len == 0 or emoji.len > 128 or std.mem.indexOfAny(u8, emoji, "\r\n") != null) {
            return ToolResult.fail("Invalid Discord emoji");
        }
        const action = root.getString(args, "action") orelse "add";
        const method: std.http.Method = if (std.mem.eql(u8, action, "add"))
            .PUT
        else if (std.mem.eql(u8, action, "remove"))
            .DELETE
        else
            return ToolResult.fail("action must be add or remove");
        const account = self.currentAccount() orelse return ToolResult.fail("No matching Discord account is configured");

        const encoded_emoji = try url_percent.encode(allocator, emoji);
        defer allocator.free(encoded_emoji);
        const url = try std.fmt.allocPrint(
            allocator,
            "https://discord.com/api/v10/channels/{s}/messages/{s}/reactions/{s}/@me",
            .{ channel_id, message_id, encoded_emoji },
        );
        defer allocator.free(url);
        const auth = try std.fmt.allocPrint(allocator, "Authorization: Bot {s}", .{account.token});
        defer allocator.free(auth);
        const response = http_util.httpRequest(allocator, method, url, null, &.{auth}, null, null) catch
            return ToolResult.fail("Discord reaction request failed");
        defer allocator.free(response);

        return ToolResult.ok(if (method == .PUT) "Reaction added" else "Reaction removed");
    }
};

test "DiscordReactionTool requires current channel context" {
    var tool = DiscordReactionTool{};
    const previous = tool.setContext(null, null, null);
    defer DiscordReactionTool.restoreContext(previous);
    const parsed = try root.parseTestArgs("{\"emoji\":\"👍\"}");
    defer parsed.deinit();
    const result = try tool.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("No Discord channel is associated with this conversation", result.error_msg.?);
}

test "DiscordReactionTool normalizes custom emoji markup" {
    try std.testing.expectEqualStrings("wave:123", DiscordReactionTool.normalizeEmoji("<:wave:123>"));
    try std.testing.expectEqualStrings("dance:456", DiscordReactionTool.normalizeEmoji("<a:dance:456>"));
    try std.testing.expectEqualStrings("👍", DiscordReactionTool.normalizeEmoji(" 👍 "));
}

test "DiscordReactionTool only uses the current account and channel" {
    const accounts = [_]config_types.DiscordConfig{.{ .account_id = "main", .token = "secret" }};
    var tool = DiscordReactionTool{ .accounts = &accounts };
    const previous = tool.setContext("other", "123456789012345678", "234567890123456789");
    defer DiscordReactionTool.restoreContext(previous);
    const parsed = try root.parseTestArgs("{\"emoji\":\"👍\",\"channel_id\":\"999\"}");
    defer parsed.deinit();
    const result = try tool.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("No matching Discord account is configured", result.error_msg.?);
}
