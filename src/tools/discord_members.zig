//! Query the complete member roster for the current Discord server.

const std = @import("std");
const root = @import("root.zig");
const config_types = @import("../config_types.zig");
const http_util = @import("../http_util.zig");

const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;

threadlocal var turn_account_id: ?[]const u8 = null;
threadlocal var turn_guild_id: ?[]const u8 = null;

pub const DiscordMembersTool = struct {
    accounts: []const config_types.DiscordConfig = &.{},

    pub const tool_name = "discord_members";
    pub const tool_description = "List every member of the current Discord server directly from Discord. Use this instead of inferring membership from conversation history.";
    pub const tool_params =
        \\{"type":"object","properties":{}}
    ;

    pub const TurnContext = struct {
        account_id: ?[]const u8,
        guild_id: ?[]const u8,
    };

    const vtable = root.ToolVTable(@This());

    pub fn tool(self: *DiscordMembersTool) Tool {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    pub fn setContext(_: *DiscordMembersTool, account_id: ?[]const u8, guild_id: ?[]const u8) TurnContext {
        const previous = TurnContext{ .account_id = turn_account_id, .guild_id = turn_guild_id };
        turn_account_id = account_id;
        turn_guild_id = guild_id;
        return previous;
    }

    pub fn restoreContext(previous: TurnContext) void {
        turn_account_id = previous.account_id;
        turn_guild_id = previous.guild_id;
    }

    fn currentAccount(self: *const DiscordMembersTool) ?config_types.DiscordConfig {
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

    fn memberName(member: std.json.ObjectMap) ?struct {
        id: []const u8,
        username: []const u8,
        display_name: []const u8,
        is_bot: bool,
    } {
        const user_value = member.get("user") orelse return null;
        if (user_value != .object) return null;
        const user = user_value.object;
        const id_value = user.get("id") orelse return null;
        if (id_value != .string) return null;
        const username = if (user.get("username")) |value| if (value == .string) value.string else id_value.string else id_value.string;
        const global_name = if (user.get("global_name")) |value| if (value == .string and value.string.len > 0) value.string else username else username;
        const display_name = if (member.get("nick")) |value| if (value == .string and value.string.len > 0) value.string else global_name else global_name;
        const is_bot = if (user.get("bot")) |value| value == .bool and value.bool else false;
        return .{
            .id = id_value.string,
            .username = username,
            .display_name = display_name,
            .is_bot = is_bot,
        };
    }

    pub fn execute(self: *DiscordMembersTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        _ = args;
        const guild_id = turn_guild_id orelse
            return ToolResult.fail("No Discord server is associated with this conversation");
        if (!isSnowflake(guild_id)) return ToolResult.fail("The current Discord server ID is invalid");
        const account = self.currentAccount() orelse return ToolResult.fail("No matching Discord account is configured");

        const auth = try std.fmt.allocPrint(allocator, "Authorization: Bot {s}", .{account.token});
        defer allocator.free(auth);
        var output: std.ArrayListUnmanaged(u8) = .empty;
        defer output.deinit(allocator);
        var output_writer: std.Io.Writer.Allocating = .fromArrayList(allocator, &output);
        const writer = &output_writer.writer;
        var after: []const u8 = "0";
        var owned_after: ?[]u8 = null;
        defer if (owned_after) |value| allocator.free(value);
        var total: usize = 0;

        while (true) {
            const url = try std.fmt.allocPrint(
                allocator,
                "https://discord.com/api/v10/guilds/{s}/members?limit=1000&after={s}",
                .{ guild_id, after },
            );
            defer allocator.free(url);
            const response = http_util.httpGetWithProxy(allocator, url, &.{auth}, null) catch
                return ToolResult.fail("Discord member query failed");
            defer allocator.free(response);
            const parsed = std.json.parseFromSlice(std.json.Value, allocator, response, .{}) catch
                return ToolResult.fail("Discord returned an invalid member response");
            defer parsed.deinit();
            if (parsed.value != .array) return ToolResult.fail("Discord returned an invalid member response");

            const batch = parsed.value.array.items;
            var last_id: ?[]const u8 = null;
            for (batch) |value| {
                if (value != .object) continue;
                const member = memberName(value.object) orelse continue;
                last_id = member.id;
                total += 1;
                try writer.print("{d}. {s}", .{ total, member.display_name });
                if (!std.mem.eql(u8, member.display_name, member.username)) try writer.print(" (@{s})", .{member.username});
                if (member.is_bot) try writer.writeAll(" [bot]");
                try writer.print(" - {s}\n", .{member.id});
            }
            if (batch.len < 1000) break;
            const next_after = last_id orelse break;
            if (owned_after) |value| allocator.free(value);
            owned_after = try allocator.dupe(u8, next_after);
            after = owned_after.?;
        }

        if (total == 0) return ToolResult.ok("No members returned for this Discord server");
        try writer.print("\nTotal: {d} members", .{total});
        output = output_writer.toArrayList();
        return .{ .success = true, .output = try output.toOwnedSlice(allocator) };
    }
};

test "DiscordMembersTool requires a guild context" {
    var tool = DiscordMembersTool{};
    const previous = tool.setContext(null, null);
    defer DiscordMembersTool.restoreContext(previous);
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try tool.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("No Discord server is associated with this conversation", result.error_msg.?);
}

test "DiscordMembersTool only uses the current account" {
    const accounts = [_]config_types.DiscordConfig{.{ .account_id = "main", .token = "secret" }};
    var tool = DiscordMembersTool{ .accounts = &accounts };
    const previous = tool.setContext("other", "123456789012345678");
    defer DiscordMembersTool.restoreContext(previous);
    const parsed = try root.parseTestArgs("{\"account_id\":\"main\",\"guild_id\":\"999\"}");
    defer parsed.deinit();
    const result = try tool.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expectEqualStrings("No matching Discord account is configured", result.error_msg.?);
}

test "DiscordMembersTool validates Discord snowflakes" {
    try std.testing.expect(DiscordMembersTool.isSnowflake("123456789012345678"));
    try std.testing.expect(!DiscordMembersTool.isSnowflake(""));
    try std.testing.expect(!DiscordMembersTool.isSnowflake("123/../../channels"));
}
