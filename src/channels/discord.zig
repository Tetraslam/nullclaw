const std = @import("std");
const std_compat = @import("compat");
const builtin = @import("builtin");
const root = @import("root.zig");
const bus_mod = @import("../bus.zig");
const fs_compat = @import("../fs_compat.zig");
const interaction_choices = @import("../interactions/choices.zig");
const control_plane = @import("../control_plane.zig");
const websocket = @import("../websocket.zig");
const thread_stacks = @import("../thread_stacks.zig");

const Atomic = @import("../portable_atomic.zig").Atomic;

const log = std.log.scoped(.discord);

const PENDING_INTERACTION_TTL_MS: u64 = 60 * std.time.ms_per_min;

const PendingInteractionOption = struct {
    id: []const u8,
    label: []const u8,
    submit_text: []const u8,

    fn deinit(self: *const PendingInteractionOption, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.label);
        allocator.free(self.submit_text);
    }
};

const PendingInteraction = struct {
    expires_at_ms: u64,
    chat_id: []const u8,
    options: []PendingInteractionOption,

    fn deinit(self: *const PendingInteraction, allocator: std.mem.Allocator) void {
        allocator.free(self.chat_id);
        for (self.options) |opt| opt.deinit(allocator);
        allocator.free(self.options);
    }
};

/// Discord channel — connects via WebSocket gateway, sends via REST API.
/// Splits messages at 2000 chars (Discord limit).
pub const DiscordChannel = struct {
    allocator: std.mem.Allocator,
    token: []const u8,
    guild_id: ?[]const u8,
    allow_bots: bool,
    account_id: []const u8 = "default",

    // Optional gateway fields (have defaults so existing init works)
    allow_from: []const []const u8 = &.{},
    require_mention: bool = false,
    mention_exempt_channels: []const []const u8 = &.{},
    intents: u32 = 37377, // GUILDS|GUILD_MESSAGES|MESSAGE_CONTENT|DIRECT_MESSAGES
    bus: ?*bus_mod.Bus = null,

    typing_mu: std_compat.sync.Mutex = .{},
    typing_handles: std.StringHashMapUnmanaged(*TypingTask) = .empty,
    interaction_mu: std_compat.sync.Mutex = .{},
    pending_interactions: std.StringHashMapUnmanaged(PendingInteraction) = .empty,
    interaction_seq: Atomic(u64) = Atomic(u64).init(1),

    // Gateway state
    running: Atomic(bool) = Atomic(bool).init(false),
    sequence: Atomic(i64) = Atomic(i64).init(0),
    heartbeat_interval_ms: Atomic(u64) = Atomic(u64).init(0),
    heartbeat_stop: Atomic(bool) = Atomic(bool).init(false),
    last_gateway_activity_ms: Atomic(i64) = Atomic(i64).init(0),
    session_id: ?[]u8 = null,
    resume_gateway_url: ?[]u8 = null,
    bot_user_id: ?[]u8 = null,
    gateway_thread: ?std.Thread = null,
    ws_fd: Atomic(SocketFd) = Atomic(SocketFd).init(invalid_socket),
    /// Count of consecutive op-7 RECONNECT events without an intervening READY.
    /// Used to implement exponential backoff and RESUME→IDENTIFY fallback.
    /// Only accessed from gatewayLoop (single-threaded write path); no atomic needed.
    consecutive_reconnects: u32 = 0,

    const SocketFd = std_compat.net.Stream.Handle;
    const invalid_socket: SocketFd = switch (builtin.os.tag) {
        .windows => std_compat.net.invalidHandle(SocketFd),
        else => -1,
    };

    pub const MAX_MESSAGE_LEN: usize = 2000;
    const MAX_UPLOAD_FILES: usize = 10;
    const MAX_UPLOAD_FILE_BYTES: usize = 50 * 1024 * 1024;
    const MAX_UPLOAD_TOTAL_BYTES: usize = 50 * 1024 * 1024;
    pub const GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json";
    const TYPING_INTERVAL_NS: u64 = 8 * std.time.ns_per_s;
    const TYPING_SLEEP_STEP_NS: u64 = 100 * std.time.ns_per_ms;
    /// Minimum stale-gateway grace window. The channel_manager checks health every 10s;
    /// allow at least 3 heartbeat intervals OR 90s before declaring the gateway dead.
    const GATEWAY_STALE_GRACE_MS: i64 = 90 * std.time.ms_per_s;
    /// After this many consecutive op-7 RECONNECT events without a successful READY,
    /// give up resuming and clear the session to force a fresh IDENTIFY.
    const MAX_RECONNECT_ATTEMPTS: u32 = 5;
    const InvalidSessionAction = enum {
        identify,
        resume_session,
    };

    const TypingTask = struct {
        channel: *DiscordChannel,
        channel_id: []const u8,
        stop_requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
        thread: ?std.Thread = null,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        token: []const u8,
        guild_id: ?[]const u8,
        allow_bots: bool,
    ) DiscordChannel {
        return .{
            .allocator = allocator,
            .token = token,
            .guild_id = guild_id,
            .allow_bots = allow_bots,
        };
    }

    /// Initialize from a full DiscordConfig, passing all fields.
    pub fn initFromConfig(allocator: std.mem.Allocator, cfg: @import("../config_types.zig").DiscordConfig) DiscordChannel {
        return .{
            .allocator = allocator,
            .token = cfg.token,
            .guild_id = cfg.guild_id,
            .allow_bots = cfg.allow_bots,
            .account_id = cfg.account_id,
            .allow_from = cfg.allow_from,
            .require_mention = cfg.require_mention,
            .mention_exempt_channels = cfg.mention_exempt_channels,
            .intents = cfg.intents,
        };
    }

    pub fn channelName(_: *DiscordChannel) []const u8 {
        return "discord";
    }

    /// Build a Discord REST API URL for sending to a channel.
    pub fn sendUrl(buf: []u8, channel_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/messages", .{channel_id});
        return w.buffered();
    }

    /// Build a Discord REST API URL for triggering typing in a channel.
    pub fn typingUrl(buf: []u8, channel_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/typing", .{channel_id});
        return w.buffered();
    }

    pub fn editMessageUrl(buf: []u8, channel_id: []const u8, message_id: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/channels/{s}/messages/{s}", .{ channel_id, message_id });
        return w.buffered();
    }

    fn interactionCallbackUrl(buf: []u8, interaction_id: []const u8, interaction_token: []const u8) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print("https://discord.com/api/v10/interactions/{s}/{s}/callback", .{ interaction_id, interaction_token });
        return w.buffered();
    }

    /// Extract bot user ID from a bot token.
    /// Discord bot tokens are base64(bot_user_id).random.hmac
    pub fn extractBotUserId(token: []const u8) ?[]const u8 {
        // Find the first '.'
        const dot_pos = std.mem.indexOf(u8, token, ".") orelse return null;
        return token[0..dot_pos];
    }

    pub fn healthCheck(self: *DiscordChannel) bool {
        return self.gatewayHealthyAt(std_compat.time.milliTimestamp());
    }

    pub fn setBus(self: *DiscordChannel, b: *bus_mod.Bus) void {
        self.bus = b;
    }

    // ── Gateway liveness helpers ──────────────────────────────────────────

    fn markGatewayActivityNow(self: *DiscordChannel) void {
        self.last_gateway_activity_ms.store(std_compat.time.milliTimestamp(), .release);
    }

    /// Returns true if the gateway appears healthy at the given wall-clock ms.
    /// Healthy conditions: not running, interval not yet received, or last activity
    /// within max(3×heartbeat_interval, GATEWAY_STALE_GRACE_MS).
    fn gatewayHealthyAt(self: *DiscordChannel, now_ms: i64) bool {
        if (!self.running.load(.acquire)) return true;

        const interval_ms = self.heartbeat_interval_ms.load(.acquire);
        if (interval_ms == 0) return true;

        const last_activity_ms = self.last_gateway_activity_ms.load(.acquire);
        if (last_activity_ms == 0 or now_ms <= last_activity_ms) return true;

        const heartbeat_window_ms: i64 = @as(i64, @intCast(interval_ms)) * 3;
        const stale_after_ms = @max(heartbeat_window_ms, GATEWAY_STALE_GRACE_MS);
        return (now_ms - last_activity_ms) <= stale_after_ms;
    }

    const ReconnectDecision = struct {
        attempt: u32,
        backoff_ms: u64,
        cleared_session: bool,
    };

    fn recordReconnectRequest(self: *DiscordChannel) ReconnectDecision {
        self.consecutive_reconnects += 1;
        const attempt = self.consecutive_reconnects;
        const shift = @min(attempt - 1, 6);
        const backoff_ms = @min(@as(u64, 1000) << @intCast(shift), 60_000);
        var cleared_session = false;

        if (attempt >= MAX_RECONNECT_ATTEMPTS) {
            self.clearSessionStateForIdentify();
            self.consecutive_reconnects = 0;
            cleared_session = true;
        }

        return .{
            .attempt = attempt,
            .backoff_ms = backoff_ms,
            .cleared_session = cleared_session,
        };
    }

    // ── Pure helper functions ─────────────────────────────────────────────

    /// Build IDENTIFY JSON payload (op=2).
    /// Example: {"op":2,"d":{"token":"Bot TOKEN","intents":37377,"properties":{"os":"linux","browser":"nullclaw","device":"nullclaw"}}}
    pub fn buildIdentifyJson(buf: []u8, token: []const u8, intents: u32) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print(
            "{{\"op\":2,\"d\":{{\"token\":\"Bot {s}\",\"intents\":{d},\"properties\":{{\"os\":\"linux\",\"browser\":\"nullclaw\",\"device\":\"nullclaw\"}}}}}}",
            .{ token, intents },
        );
        return w.buffered();
    }

    /// Build HEARTBEAT JSON payload (op=1).
    /// seq==0 → {"op":1,"d":null}, else {"op":1,"d":42}
    pub fn buildHeartbeatJson(buf: []u8, seq: i64) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        if (seq == 0) {
            try w.writeAll("{\"op\":1,\"d\":null}");
        } else {
            try w.print("{{\"op\":1,\"d\":{d}}}", .{seq});
        }
        return w.buffered();
    }

    /// Build RESUME JSON payload (op=6).
    /// {"op":6,"d":{"token":"Bot TOKEN","session_id":"SESSION","seq":42}}
    pub fn buildResumeJson(buf: []u8, token: []const u8, session_id: []const u8, seq: i64) ![]const u8 {
        var w: std.Io.Writer = .fixed(buf);
        try w.print(
            "{{\"op\":6,\"d\":{{\"token\":\"Bot {s}\",\"session_id\":\"{s}\",\"seq\":{d}}}}}",
            .{ token, session_id, seq },
        );
        return w.buffered();
    }

    /// Parse gateway host from wss:// URL.
    /// "wss://us-east1.gateway.discord.gg" -> "us-east1.gateway.discord.gg"
    /// "wss://gateway.discord.gg/?v=10&encoding=json" -> "gateway.discord.gg"
    /// Returns slice into wss_url (no allocation).
    pub fn parseGatewayHost(wss_url: []const u8) []const u8 {
        // Strip scheme prefix if present
        const no_scheme = if (std.mem.startsWith(u8, wss_url, "wss://"))
            wss_url[6..]
        else if (std.mem.startsWith(u8, wss_url, "ws://"))
            wss_url[5..]
        else
            wss_url;

        // Strip path (everything after first '/' or '?')
        const slash_pos = std.mem.indexOf(u8, no_scheme, "/");
        const query_pos = std.mem.indexOf(u8, no_scheme, "?");

        const end = blk: {
            if (slash_pos != null and query_pos != null) {
                break :blk @min(slash_pos.?, query_pos.?);
            } else if (slash_pos != null) {
                break :blk slash_pos.?;
            } else if (query_pos != null) {
                break :blk query_pos.?;
            } else {
                break :blk no_scheme.len;
            }
        };

        return no_scheme[0..end];
    }

    /// Check if bot is mentioned in message content.
    /// Returns true if "<@BOT_ID>" or "<@!BOT_ID>" appears in content.
    pub fn isMentioned(content: []const u8, bot_user_id: []const u8) bool {
        // Check for <@BOT_ID>
        var buf1: [64]u8 = undefined;
        const mention1 = std.fmt.bufPrint(&buf1, "<@{s}>", .{bot_user_id}) catch return false;
        if (std.mem.indexOf(u8, content, mention1) != null) return true;

        // Check for <@!BOT_ID>
        var buf2: [64]u8 = undefined;
        const mention2 = std.fmt.bufPrint(&buf2, "<@!{s}>", .{bot_user_id}) catch return false;
        if (std.mem.indexOf(u8, content, mention2) != null) return true;

        return false;
    }

    fn isMentionExemptChannel(self: *const DiscordChannel, channel_id: []const u8) bool {
        for (self.mention_exempt_channels) |allowed| {
            if (std.mem.eql(u8, allowed, channel_id)) return true;
        }
        return false;
    }

    fn isReplyToBot(d_obj: std.json.ObjectMap, bot_user_id: []const u8) bool {
        if (bot_user_id.len == 0) return false;
        const message_type = d_obj.get("type") orelse return false;
        switch (message_type) {
            .integer => |value| if (value != 19) return false,
            else => return false,
        }
        const referenced_message = d_obj.get("referenced_message") orelse return false;
        const referenced_obj = switch (referenced_message) {
            .object => |o| o,
            else => return false,
        };
        const author_val = referenced_obj.get("author") orelse return false;
        const author_obj = switch (author_val) {
            .object => |o| o,
            else => return false,
        };
        const author_id_val = author_obj.get("id") orelse return false;
        const author_id = switch (author_id_val) {
            .string => |s| s,
            else => return false,
        };
        return std.mem.eql(u8, author_id, bot_user_id);
    }

    // ── Channel vtable ──────────────────────────────────────────────

    /// Send a message to a Discord channel via REST API.
    /// Splits at MAX_MESSAGE_LEN (2000 chars).
    pub fn sendMessage(self: *DiscordChannel, channel_id: []const u8, text: []const u8) !void {
        var it = root.splitMessage(text, MAX_MESSAGE_LEN);
        while (it.next()) |chunk| {
            try self.sendChunk(channel_id, chunk);
        }
    }

    const ParsedOutboundMessage = struct {
        text: []u8,
        files: [][]const u8,

        fn deinit(self: *const ParsedOutboundMessage, allocator: std.mem.Allocator) void {
            allocator.free(self.text);
            allocator.free(self.files);
        }
    };

    fn isAttachmentMarkerKind(kind: []const u8) bool {
        return std.ascii.eqlIgnoreCase(kind, "image") or
            std.ascii.eqlIgnoreCase(kind, "photo") or
            std.ascii.eqlIgnoreCase(kind, "document") or
            std.ascii.eqlIgnoreCase(kind, "file") or
            std.ascii.eqlIgnoreCase(kind, "video") or
            std.ascii.eqlIgnoreCase(kind, "audio") or
            std.ascii.eqlIgnoreCase(kind, "voice");
    }

    fn isRemoteAttachment(target: []const u8) bool {
        return std.mem.startsWith(u8, target, "https://") or std.mem.startsWith(u8, target, "http://");
    }

    fn matchingBracket(text: []const u8, open: usize) ?usize {
        var depth: usize = 1;
        var cursor = open + 1;
        while (cursor < text.len) : (cursor += 1) {
            switch (text[cursor]) {
                '[' => depth += 1,
                ']' => {
                    depth -= 1;
                    if (depth == 0) return cursor;
                },
                else => {},
            }
        }
        return null;
    }

    fn appendAttachmentTarget(
        allocator: std.mem.Allocator,
        text: *std.ArrayListUnmanaged(u8),
        files: *std.ArrayListUnmanaged([]const u8),
        target: []const u8,
    ) !void {
        if (isRemoteAttachment(target)) {
            if (text.items.len > 0 and text.items[text.items.len - 1] != '\n') try text.append(allocator, '\n');
            try text.appendSlice(allocator, target);
            return;
        }
        if (files.items.len >= MAX_UPLOAD_FILES) return error.TooManyAttachments;
        try files.append(allocator, target);
    }

    fn parseOutboundMessage(
        allocator: std.mem.Allocator,
        content: []const u8,
        media: []const []const u8,
    ) !ParsedOutboundMessage {
        var text: std.ArrayListUnmanaged(u8) = .empty;
        errdefer text.deinit(allocator);
        var files: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer files.deinit(allocator);

        var cursor: usize = 0;
        while (cursor < content.len) {
            const open = std.mem.indexOfPos(u8, content, cursor, "[") orelse {
                try text.appendSlice(allocator, content[cursor..]);
                break;
            };
            try text.appendSlice(allocator, content[cursor..open]);
            const close = matchingBracket(content, open) orelse {
                try text.appendSlice(allocator, content[open..]);
                break;
            };
            const marker = content[open + 1 .. close];
            const colon = std.mem.indexOfScalar(u8, marker, ':');
            if (colon) |at| {
                const target = std.mem.trim(u8, marker[at + 1 ..], " ");
                if (target.len > 0 and isAttachmentMarkerKind(marker[0..at])) {
                    try appendAttachmentTarget(allocator, &text, &files, target);
                    cursor = close + 1;
                    continue;
                }
            }
            try text.appendSlice(allocator, content[open .. close + 1]);
            cursor = close + 1;
        }
        for (media) |target| try appendAttachmentTarget(allocator, &text, &files, target);

        const trimmed = std.mem.trim(u8, text.items, " \t\r\n");
        const owned_text = try allocator.dupe(u8, trimmed);
        errdefer allocator.free(owned_text);
        const owned_files = try files.toOwnedSlice(allocator);
        text.deinit(allocator);
        return .{ .text = owned_text, .files = owned_files };
    }

    fn safeUploadFilename(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
        const basename = std_compat.fs.path.basename(path);
        const source = if (basename.len > 0) basename else "attachment";
        const result = try allocator.dupe(u8, source);
        for (result) |*ch| {
            if (ch.* < 0x20 or ch.* == 0x7f or ch.* == '"' or ch.* == '\\') ch.* = '_';
        }
        return result;
    }

    fn appendFmt(
        list: *std.ArrayListUnmanaged(u8),
        allocator: std.mem.Allocator,
        comptime format: []const u8,
        args: anytype,
    ) !void {
        var allocating: std.Io.Writer.Allocating = .fromArrayList(allocator, list);
        try allocating.writer.print(format, args);
        list.* = allocating.toArrayList();
    }

    fn sendMultipart(
        self: *DiscordChannel,
        channel_id: []const u8,
        text: []const u8,
        files: []const []const u8,
        components_json: ?[]const u8,
    ) !void {
        if (files.len == 0) return error.NoAttachments;
        if (files.len > MAX_UPLOAD_FILES) return error.TooManyAttachments;

        var filenames: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (filenames.items) |name| self.allocator.free(name);
            filenames.deinit(self.allocator);
        }
        var file_data: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (file_data.items) |data| self.allocator.free(data);
            file_data.deinit(self.allocator);
        }
        var total_file_bytes: usize = 0;
        for (files) |path| {
            const name = try safeUploadFilename(self.allocator, path);
            filenames.append(self.allocator, name) catch |err| {
                self.allocator.free(name);
                return err;
            };
            const data = try fs_compat.readFileAlloc(std_compat.fs.cwd(), self.allocator, path, MAX_UPLOAD_FILE_BYTES);
            total_file_bytes = std.math.add(usize, total_file_bytes, data.len) catch {
                self.allocator.free(data);
                return error.AttachmentsTooLarge;
            };
            if (total_file_bytes > MAX_UPLOAD_TOTAL_BYTES) {
                self.allocator.free(data);
                return error.AttachmentsTooLarge;
            }
            file_data.append(self.allocator, data) catch |err| {
                self.allocator.free(data);
                return err;
            };
        }

        var payload: std.ArrayListUnmanaged(u8) = .empty;
        defer payload.deinit(self.allocator);
        try payload.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&payload, self.allocator, text);
        try payload.appendSlice(self.allocator, ",\"attachments\":[");
        for (filenames.items, 0..) |name, index| {
            if (index > 0) try payload.append(self.allocator, ',');
            try appendFmt(&payload, self.allocator, "{{\"id\":{d},\"filename\":", .{index});
            try root.json_util.appendJsonString(&payload, self.allocator, name);
            try payload.append(self.allocator, '}');
        }
        try payload.append(self.allocator, ']');
        if (components_json) |components| {
            try payload.appendSlice(self.allocator, ",\"components\":");
            try payload.appendSlice(self.allocator, components);
        }
        try payload.append(self.allocator, '}');

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        var boundary_buf: [64]u8 = undefined;
        const boundary = try std.fmt.bufPrint(&boundary_buf, "nullclaw-{x}-{x}", .{
            std_compat.crypto.random.int(u64),
            std_compat.crypto.random.int(u64),
        });
        try appendFmt(&body, self.allocator, "--{s}\r\nContent-Disposition: form-data; name=\"payload_json\"\r\nContent-Type: application/json\r\n\r\n", .{boundary});
        try body.appendSlice(self.allocator, payload.items);
        try body.appendSlice(self.allocator, "\r\n");
        for (file_data.items, filenames.items, 0..) |data, name, index| {
            try appendFmt(
                &body,
                self.allocator,
                "--{s}\r\nContent-Disposition: form-data; name=\"files[{d}]\"; filename=\"{s}\"\r\nContent-Type: application/octet-stream\r\n\r\n",
                .{ boundary, index, name },
            );
            try body.appendSlice(self.allocator, data);
            try body.appendSlice(self.allocator, "\r\n");
        }
        try appendFmt(&body, self.allocator, "--{s}--\r\n", .{boundary});

        var url_buf: [256]u8 = undefined;
        const url = try sendUrl(&url_buf, channel_id);
        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        var content_type_buf: [128]u8 = undefined;
        const content_type = try std.fmt.bufPrint(&content_type_buf, "multipart/form-data; boundary={s}", .{boundary});
        const resp = root.http_util.httpRequest(self.allocator, .POST, url, body.items, &.{auth_writer.buffered()}, content_type, null) catch |err| {
            log.err("Discord API multipart POST failed: {}", .{err});
            return error.DiscordApiError;
        };
        self.allocator.free(resp);
    }

    fn sendMessageWithMedia(self: *DiscordChannel, channel_id: []const u8, content: []const u8, media: []const []const u8) !void {
        const parsed = try parseOutboundMessage(self.allocator, content, media);
        defer parsed.deinit(self.allocator);
        if (parsed.files.len == 0) return self.sendMessage(channel_id, parsed.text);
        if (parsed.text.len > MAX_MESSAGE_LEN) {
            try self.sendMessage(channel_id, parsed.text);
            return self.sendMultipart(channel_id, "", parsed.files, null);
        }
        return self.sendMultipart(channel_id, parsed.text, parsed.files, null);
    }

    /// Send a Discord typing indicator (best-effort, errors ignored).
    pub fn sendTypingIndicator(self: *DiscordChannel, channel_id: []const u8) void {
        if (builtin.is_test) return;
        if (channel_id.len == 0) return;

        var url_buf: [256]u8 = undefined;
        const url = typingUrl(&url_buf, channel_id) catch return;

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        auth_writer.print("Authorization: Bot {s}", .{self.token}) catch return;
        const auth_header = auth_writer.buffered();

        const resolve_entry = root.http_util.buildSafeResolveEntryForRemoteUrl(self.allocator, url) catch return;
        defer if (resolve_entry) |entry| self.allocator.free(entry);
        const resp = root.http_util.curlPostWithProxyAndResolve(
            self.allocator,
            url,
            "{}",
            &.{auth_header},
            null,
            "5",
            resolve_entry,
        ) catch return;
        self.allocator.free(resp);
    }

    pub fn startTyping(self: *DiscordChannel, channel_id: []const u8) !void {
        if (!self.running.load(.acquire)) return;
        if (channel_id.len == 0) return;

        try self.stopTyping(channel_id);

        const key_copy = try self.allocator.dupe(u8, channel_id);
        errdefer self.allocator.free(key_copy);

        const task = try self.allocator.create(TypingTask);
        errdefer self.allocator.destroy(task);
        task.* = .{
            .channel = self,
            .channel_id = key_copy,
        };

        // typingLoop performs full HTTPS requests (http.Client + TLS) every
        // interval, which needs far more headroom than the auxiliary-loop
        // stack. std.crypto.tls.Client.init alone does large inline memcpys
        // that overflow a 512KB stack and crash the whole process. Use the
        // heavy runtime stack for this thread.
        task.thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.HEAVY_RUNTIME_STACK_SIZE }, typingLoop, .{task});
        errdefer {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
        }

        self.typing_mu.lock();
        defer self.typing_mu.unlock();
        try self.typing_handles.put(self.allocator, key_copy, task);
    }

    pub fn stopTyping(self: *DiscordChannel, channel_id: []const u8) !void {
        var removed_key: ?[]u8 = null;
        var removed_task: ?*TypingTask = null;

        self.typing_mu.lock();
        if (self.typing_handles.fetchRemove(channel_id)) |entry| {
            removed_key = @constCast(entry.key);
            removed_task = entry.value;
        }
        self.typing_mu.unlock();

        if (removed_task) |task| {
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
            self.allocator.destroy(task);
        }
        if (removed_key) |key| {
            self.allocator.free(key);
        }
    }

    fn stopAllTyping(self: *DiscordChannel) void {
        self.typing_mu.lock();
        var handles = self.typing_handles;
        self.typing_handles = .empty;
        self.typing_mu.unlock();

        var it = handles.iterator();
        while (it.next()) |entry| {
            const task = entry.value_ptr.*;
            task.stop_requested.store(true, .release);
            if (task.thread) |t| t.join();
            self.allocator.destroy(task);
            self.allocator.free(@constCast(entry.key_ptr.*));
        }
        handles.deinit(self.allocator);
    }

    fn typingLoop(task: *TypingTask) void {
        while (!task.stop_requested.load(.acquire)) {
            task.channel.sendTypingIndicator(task.channel_id);
            var elapsed: u64 = 0;
            while (elapsed < TYPING_INTERVAL_NS and !task.stop_requested.load(.acquire)) {
                std_compat.thread.sleep(TYPING_SLEEP_STEP_NS);
                elapsed += TYPING_SLEEP_STEP_NS;
            }
        }
    }

    fn sendChunk(self: *DiscordChannel, channel_id: []const u8, text: []const u8) !void {
        var url_buf: [256]u8 = undefined;
        const url = try sendUrl(&url_buf, channel_id);

        // Build JSON body: {"content":"..."}
        var body_list: std.ArrayListUnmanaged(u8) = .empty;
        defer body_list.deinit(self.allocator);

        try body_list.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body_list, self.allocator, text);
        try body_list.appendSlice(self.allocator, "}");

        // Build auth header value: "Authorization: Bot <token>"
        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.httpPostJsonWithProxy(self.allocator, url, body_list.items, &.{auth_header}, null) catch |err| {
            log.err("Discord API POST failed: {}", .{err});
            return error.DiscordApiError;
        };
        self.allocator.free(resp);
    }

    fn sendJsonMethod(self: *DiscordChannel, method: []const u8, url: []const u8, body: []const u8) !void {
        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        const http_method: std.http.Method = if (std.mem.eql(u8, method, "PATCH")) .PATCH else .POST;
        const resp = root.http_util.httpRequest(self.allocator, http_method, url, body, &.{auth_writer.buffered()}, "application/json", null) catch return error.DiscordApiError;
        self.allocator.free(resp);
    }

    fn nextInteractionToken(self: *DiscordChannel) ![]u8 {
        const seq = self.interaction_seq.fetchAdd(1, .monotonic) + 1;
        var buf: [32]u8 = undefined;
        const token = try std.fmt.bufPrint(&buf, "{x}", .{seq});
        return self.allocator.dupe(u8, token);
    }

    fn buildChoicesDirectiveFromPayload(
        self: *DiscordChannel,
        choices: []const root.Channel.OutboundChoice,
    ) !interaction_choices.ChoicesDirective {
        if (choices.len < interaction_choices.MIN_OPTIONS or choices.len > interaction_choices.MAX_OPTIONS) {
            return error.InvalidChoices;
        }

        var options = try self.allocator.alloc(interaction_choices.ChoiceOption, choices.len);
        var built: usize = 0;
        errdefer {
            for (options[0..built]) |opt| opt.deinit(self.allocator);
            self.allocator.free(options);
        }

        for (choices, 0..) |choice, i| {
            options[i] = .{
                .id = try self.allocator.dupe(u8, choice.id),
                .label = try self.allocator.dupe(u8, choice.label),
                .submit_text = try self.allocator.dupe(u8, choice.submit_text),
            };
            built += 1;
        }

        return .{
            .version = 1,
            .options = options,
        };
    }

    fn buildComponentsJson(
        self: *DiscordChannel,
        directive: interaction_choices.ChoicesDirective,
        token: []const u8,
    ) ![]u8 {
        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(self.allocator);

        try out.appendSlice(self.allocator, "[");
        var row_start: usize = 0;
        while (row_start < directive.options.len) {
            if (row_start > 0) try out.appendSlice(self.allocator, ",");
            try out.appendSlice(self.allocator, "{\"type\":1,\"components\":[");

            const row_end = @min(row_start + 5, directive.options.len);
            for (directive.options[row_start..row_end], row_start..) |opt, idx| {
                if (idx > row_start) try out.appendSlice(self.allocator, ",");
                var cb_buf: [100]u8 = undefined;
                const custom_id = try interaction_choices.formatChoiceCallbackData(&cb_buf, token, opt.id, 100);
                try out.appendSlice(self.allocator, "{\"type\":2,\"style\":1,\"label\":");
                try root.json_util.appendJsonString(&out, self.allocator, opt.label);
                try out.appendSlice(self.allocator, ",\"custom_id\":");
                try root.json_util.appendJsonString(&out, self.allocator, custom_id);
                try out.appendSlice(self.allocator, "}");
            }
            try out.appendSlice(self.allocator, "]}");
            row_start = row_end;
        }
        try out.appendSlice(self.allocator, "]");
        return try out.toOwnedSlice(self.allocator);
    }

    fn registerPendingInteraction(
        self: *DiscordChannel,
        token: []const u8,
        chat_id: []const u8,
        directive: interaction_choices.ChoicesDirective,
    ) !void {
        var options = try self.allocator.alloc(PendingInteractionOption, directive.options.len);
        var built: usize = 0;
        errdefer {
            for (options[0..built]) |opt| opt.deinit(self.allocator);
            self.allocator.free(options);
        }

        for (directive.options, 0..) |opt, i| {
            options[i] = .{
                .id = try self.allocator.dupe(u8, opt.id),
                .label = try self.allocator.dupe(u8, opt.label),
                .submit_text = try self.allocator.dupe(u8, opt.submit_text),
            };
            built += 1;
        }

        const key = try self.allocator.dupe(u8, token);
        errdefer self.allocator.free(key);
        const chat_copy = try self.allocator.dupe(u8, chat_id);
        errdefer self.allocator.free(chat_copy);

        const now_ms = std_compat.time.milliTimestamp();
        if (now_ms < 0) return error.InvalidTimestamp;
        self.pruneExpiredInteractions();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();
        try self.pending_interactions.put(self.allocator, key, .{
            .expires_at_ms = @as(u64, @intCast(now_ms)) + PENDING_INTERACTION_TTL_MS,
            .chat_id = chat_copy,
            .options = options,
        });
    }

    fn pruneExpiredInteractions(self: *DiscordChannel) void {
        const now_ms: i64 = std_compat.time.milliTimestamp();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();

        var it = self.pending_interactions.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.expires_at_ms <= @as(u64, @intCast(now_ms))) {
                const key = entry.key_ptr.*;
                if (self.pending_interactions.fetchRemove(key)) |kv| {
                    self.allocator.free(@constCast(kv.key));
                    kv.value.deinit(self.allocator);
                }
            }
        }
    }

    const CallbackSelection = union(enum) {
        ok: []u8,
        not_found,
        expired,
        invalid_chat,
        invalid_option,
    };

    fn consumeCallbackSelection(
        self: *DiscordChannel,
        allocator: std.mem.Allocator,
        token: []const u8,
        option_id: []const u8,
        chat_id: []const u8,
    ) !CallbackSelection {
        self.pruneExpiredInteractions();
        self.interaction_mu.lock();
        defer self.interaction_mu.unlock();

        const pending_ptr = self.pending_interactions.getPtr(token) orelse return .not_found;
        if (pending_ptr.expires_at_ms <= @as(u64, @intCast(std_compat.time.milliTimestamp()))) {
            if (self.pending_interactions.fetchRemove(token)) |kv| {
                self.allocator.free(@constCast(kv.key));
                kv.value.deinit(self.allocator);
            }
            return .expired;
        }
        if (!std.mem.eql(u8, pending_ptr.chat_id, chat_id)) return .invalid_chat;

        for (pending_ptr.options) |opt| {
            if (!std.mem.eql(u8, opt.id, option_id)) continue;
            const submit_text = try allocator.dupe(u8, opt.submit_text);
            if (self.pending_interactions.fetchRemove(token)) |kv| {
                self.allocator.free(@constCast(kv.key));
                kv.value.deinit(self.allocator);
            }
            return .{ .ok = submit_text };
        }
        return .invalid_option;
    }

    fn deinitPendingInteractions(self: *DiscordChannel) void {
        self.interaction_mu.lock();
        var pending = self.pending_interactions;
        self.pending_interactions = .empty;
        self.interaction_mu.unlock();

        var it = pending.iterator();
        while (it.next()) |entry| {
            self.allocator.free(@constCast(entry.key_ptr.*));
            entry.value_ptr.deinit(self.allocator);
        }
        pending.deinit(self.allocator);
    }

    fn sendRichMessage(self: *DiscordChannel, channel_id: []const u8, payload: root.Channel.OutboundPayload) !void {
        var media = try self.allocator.alloc([]const u8, payload.attachments.len);
        defer self.allocator.free(media);
        for (payload.attachments, 0..) |attachment, index| media[index] = attachment.target;

        if (payload.choices.len == 0) return self.sendMessageWithMedia(channel_id, payload.text, media);

        const parsed = try parseOutboundMessage(self.allocator, payload.text, media);
        defer parsed.deinit(self.allocator);
        if (parsed.text.len > MAX_MESSAGE_LEN) return error.MessageTooLong;

        var directive = try self.buildChoicesDirectiveFromPayload(payload.choices);
        defer directive.deinit(self.allocator);

        const token = try self.nextInteractionToken();
        defer self.allocator.free(token);
        const components_json = try self.buildComponentsJson(directive, token);
        defer self.allocator.free(components_json);

        if (parsed.files.len > 0) {
            try self.sendMultipart(channel_id, parsed.text, parsed.files, components_json);
            try self.registerPendingInteraction(token, channel_id, directive);
            return;
        }

        var url_buf: [256]u8 = undefined;
        const url = try sendUrl(&url_buf, channel_id);

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body, self.allocator, parsed.text);
        try body.appendSlice(self.allocator, ",\"components\":");
        try body.appendSlice(self.allocator, components_json);
        try body.appendSlice(self.allocator, "}");

        var auth_buf: [512]u8 = undefined;
        var auth_writer: std.Io.Writer = .fixed(&auth_buf);
        try auth_writer.print("Authorization: Bot {s}", .{self.token});
        const auth_header = auth_writer.buffered();

        const resp = root.http_util.httpPostJsonWithProxy(self.allocator, url, body.items, &.{auth_header}, null) catch |err| {
            log.err("Discord API rich POST failed: {}", .{err});
            return error.DiscordApiError;
        };
        defer self.allocator.free(resp);

        try self.registerPendingInteraction(token, channel_id, directive);
    }

    fn editRichMessage(self: *DiscordChannel, edit: root.Channel.MessageEdit) !void {
        if (edit.payload.attachments.len > 0) return error.NotSupported;

        var components_json: ?[]u8 = null;
        defer if (components_json) |json| self.allocator.free(json);

        if (edit.payload.choices.len > 0) {
            var directive = try self.buildChoicesDirectiveFromPayload(edit.payload.choices);
            defer directive.deinit(self.allocator);

            const token = try self.nextInteractionToken();
            defer self.allocator.free(token);
            components_json = try self.buildComponentsJson(directive, token);
            try self.registerPendingInteraction(token, edit.target, directive);
        }

        var body: std.ArrayListUnmanaged(u8) = .empty;
        defer body.deinit(self.allocator);
        try body.appendSlice(self.allocator, "{\"content\":");
        try root.json_util.appendJsonString(&body, self.allocator, edit.payload.text);
        if (components_json) |json| {
            try body.appendSlice(self.allocator, ",\"components\":");
            try body.appendSlice(self.allocator, json);
        } else {
            try body.appendSlice(self.allocator, ",\"components\":[]");
        }
        try body.appendSlice(self.allocator, "}");

        var url_buf: [256]u8 = undefined;
        const url = try editMessageUrl(&url_buf, edit.target, edit.message_id);
        try self.sendJsonMethod("PATCH", url, body.items);
    }

    fn answerInteraction(self: *DiscordChannel, interaction_id: []const u8, interaction_token: []const u8, message: ?[]const u8) void {
        if (builtin.is_test) return;

        var url_buf: [512]u8 = undefined;
        const url = interactionCallbackUrl(&url_buf, interaction_id, interaction_token) catch return;

        const body = if (message) |msg|
            std.fmt.allocPrint(self.allocator, "{{\"type\":4,\"data\":{{\"content\":{f},\"flags\":64}}}}", .{std.json.fmt(msg, .{})})
        else
            self.allocator.dupe(u8, "{\"type\":6}");
        const owned_body = body catch return;
        defer self.allocator.free(owned_body);

        const resp = root.http_util.httpPostJsonWithProxy(self.allocator, url, owned_body, &.{}, null) catch return;
        self.allocator.free(resp);
    }

    // ── Gateway ──────────────────────────────────────────────────────

    fn vtableStart(ptr: *anyopaque) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        self.markGatewayActivityNow();
        self.running.store(true, .release);
        self.gateway_thread = try std.Thread.spawn(.{ .stack_size = thread_stacks.HEAVY_RUNTIME_STACK_SIZE }, gatewayLoop, .{self});
    }

    fn vtableStop(ptr: *anyopaque) void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        self.running.store(false, .release);
        self.heartbeat_stop.store(true, .release);
        self.stopAllTyping();
        self.deinitPendingInteractions();
        // Shut down the socket to unblock a blocking readv in the gateway thread.
        // close() on a remote TCP socket does NOT interrupt a blocked readv in another
        // thread on POSIX/macOS — the kernel holds its own file-description reference
        // for the blocked reader.  shutdown(SHUT_RDWR) explicitly delivers EOF to the
        // blocked reader, causing it to return 0 (EndOfStream → ConnectionClosed).
        // NOTE: No unit test for this path — requires a live remote TCP connection and
        // concurrent thread; covered by manual integration testing against a live gateway.
        const fd = self.ws_fd.load(.acquire);
        if (fd != invalid_socket) {
            (std_compat.net.Stream{ .handle = fd }).shutdown(.both) catch {};
        }
        if (self.gateway_thread) |t| {
            t.join();
            self.gateway_thread = null;
        }
        // Free session state
        if (self.session_id) |s| {
            self.allocator.free(s);
            self.session_id = null;
        }
        if (self.resume_gateway_url) |u| {
            self.allocator.free(u);
            self.resume_gateway_url = null;
        }
        if (self.bot_user_id) |u| {
            self.allocator.free(u);
            self.bot_user_id = null;
        }
    }

    fn vtableSend(ptr: *anyopaque, target: []const u8, message: []const u8, media: []const []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.sendMessageWithMedia(target, message, media);
    }

    fn vtableSendRich(ptr: *anyopaque, target: []const u8, payload: root.Channel.OutboundPayload) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.sendRichMessage(target, payload);
    }

    fn vtableEditMessage(ptr: *anyopaque, edit: root.Channel.MessageEdit) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.editRichMessage(edit);
    }

    fn vtableName(ptr: *anyopaque) []const u8 {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.channelName();
    }

    fn vtableHealthCheck(ptr: *anyopaque) bool {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        return self.healthCheck();
    }

    fn vtableStartTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.startTyping(recipient);
    }

    fn vtableStopTyping(ptr: *anyopaque, recipient: []const u8) anyerror!void {
        const self: *DiscordChannel = @ptrCast(@alignCast(ptr));
        try self.stopTyping(recipient);
    }

    pub const vtable = root.Channel.VTable{
        .start = &vtableStart,
        .stop = &vtableStop,
        .send = &vtableSend,
        .sendRich = &vtableSendRich,
        .editMessage = &vtableEditMessage,
        .name = &vtableName,
        .healthCheck = &vtableHealthCheck,
        .startTyping = &vtableStartTyping,
        .stopTyping = &vtableStopTyping,
    };

    pub fn channel(self: *DiscordChannel) root.Channel {
        return .{ .ptr = @ptrCast(self), .vtable = &vtable };
    }

    // ── Gateway loop ─────────────────────────────────────────────────

    fn gatewayLoop(self: *DiscordChannel) void {
        while (self.running.load(.acquire)) {
            var backoff_ms: u64 = 5000;
            self.runGatewayOnce() catch |err| switch (err) {
                error.ShouldReconnect => {
                    // OP7 RECONNECT is a normal control signal from Discord.
                    // Use exponential backoff to avoid rate-limiting reconnect storms:
                    // attempt 1→1s, 2→2s, 3→4s, 4→8s, 5→16s, 6→32s, 7+→60s.
                    const reconnect = self.recordReconnectRequest();
                    backoff_ms = reconnect.backoff_ms;
                    log.info("Discord gateway reconnect requested by server (attempt {d}, backoff {d}ms)", .{ reconnect.attempt, reconnect.backoff_ms });
                    if (reconnect.cleared_session) log.warn(
                        "Discord: {d} consecutive reconnects without READY; clearing session for fresh IDENTIFY",
                        .{reconnect.attempt},
                    );
                },
                else => {
                    self.consecutive_reconnects = 0;
                    log.warn("Discord gateway error: {}", .{err});
                },
            };
            if (!self.running.load(.acquire)) break;
            // Backoff between reconnects (interruptible).
            var slept: u64 = 0;
            while (slept < backoff_ms and self.running.load(.acquire)) {
                std_compat.thread.sleep(100 * std.time.ns_per_ms);
                slept += 100;
            }
        }
    }

    fn runGatewayOnce(self: *DiscordChannel) !void {
        // Refresh the watchdog baseline before DNS/TCP/TLS. A restart should get a
        // full stale-gateway grace window instead of inheriting the old dead socket's
        // last activity timestamp.
        self.markGatewayActivityNow();

        // Determine host
        const default_host = "gateway.discord.gg";
        const host: []const u8 = if (self.resume_gateway_url) |u| parseGatewayHost(u) else default_host;

        // Phase 1: DNS + TCP only.
        // Storing ws_fd before TLS init lets vtableStop interrupt a stalled TLS handshake
        // via shutdown(.both), which delivers EOF to the blocked readv immediately.
        const ws_stream = websocket.WsClient.connectTcp(self.allocator, host, 443) catch |err| {
            // TCP failed — clear stale resume URL so next attempt uses gateway.discord.gg.
            if (self.resume_gateway_url) |u| {
                self.allocator.free(u);
                self.resume_gateway_url = null;
            }
            return err;
        };
        // Store fd now so vtableStop can interrupt even during the TLS handshake below.
        self.ws_fd.store(ws_stream.handle, .release);

        // Phase 2: TLS init + WebSocket handshake (interruptible via vtableStop shutdown).
        var ws = websocket.WsClient.connectFromStream(
            self.allocator,
            ws_stream,
            host,
            "/?v=10&encoding=json",
            &.{},
        ) catch |err| {
            // connectFromStream closed ws_stream on failure; clear the now-invalid fd.
            self.ws_fd.store(invalid_socket, .release);
            // Clear stale resume URL same as TCP failure path above.
            if (self.resume_gateway_url) |u| {
                self.allocator.free(u);
                self.resume_gateway_url = null;
            }
            return err;
        };
        // ws now owns ws_stream; the defer block below handles ws_fd reset + ws.deinit().

        // Start heartbeat thread — on failure, clean up ws manually (no errdefer to avoid
        // double-deinit with the defer block below once spawn succeeds).
        self.heartbeat_stop.store(false, .release);
        self.heartbeat_interval_ms.store(0, .release);
        const hbt = std.Thread.spawn(.{ .stack_size = thread_stacks.AUXILIARY_LOOP_STACK_SIZE }, heartbeatLoop, .{ self, &ws }) catch |err| {
            ws.deinit();
            return err;
        };
        defer {
            self.heartbeat_stop.store(true, .release);
            hbt.join();
            self.ws_fd.store(invalid_socket, .release);
            ws.deinit();
        }

        // Wait for HELLO (first message)
        const hello_text = try ws.readTextMessage() orelse return error.ConnectionClosed;
        defer self.allocator.free(hello_text);
        try self.handleHello(&ws, hello_text);
        // Record activity after HELLO so the health watchdog has a baseline timestamp.
        self.markGatewayActivityNow();

        // IDENTIFY or RESUME
        if (self.session_id != null) {
            try self.sendResumePayload(&ws);
        } else {
            self.sequence.store(0, .release);
            try self.sendIdentifyPayload(&ws);
        }

        // Main read loop
        while (self.running.load(.acquire)) {
            const maybe_text = ws.readTextMessage() catch |err| {
                log.warn("Discord gateway read failed: {}", .{err});
                break;
            };
            const text = maybe_text orelse break;
            defer self.allocator.free(text);
            self.markGatewayActivityNow();
            self.handleGatewayMessage(&ws, text) catch |err| {
                if (err == error.ShouldReconnect) return err;
                log.err("Discord gateway msg error: {}", .{err});
            };
        }
    }

    // ── Heartbeat thread ─────────────────────────────────────────────

    fn heartbeatLoop(self: *DiscordChannel, ws: *websocket.WsClient) void {
        // Wait for interval to be set
        while (!self.heartbeat_stop.load(.acquire) and self.heartbeat_interval_ms.load(.acquire) == 0) {
            std_compat.thread.sleep(10 * std.time.ns_per_ms);
        }
        while (!self.heartbeat_stop.load(.acquire)) {
            const interval_ms = self.heartbeat_interval_ms.load(.acquire);
            var elapsed: u64 = 0;
            while (elapsed < interval_ms) {
                if (self.heartbeat_stop.load(.acquire)) return;
                std_compat.thread.sleep(100 * std.time.ns_per_ms);
                elapsed += 100;
            }
            if (self.heartbeat_stop.load(.acquire)) return;

            const seq = self.sequence.load(.acquire);
            var hb_buf: [64]u8 = undefined;
            const hb_json = buildHeartbeatJson(&hb_buf, seq) catch continue;
            ws.writeText(hb_json) catch |err| {
                log.warn("Discord heartbeat failed: {}", .{err});
            };
        }
    }

    // ── Message handlers ─────────────────────────────────────────────

    /// Parse HELLO payload and store heartbeat interval.
    fn handleHello(self: *DiscordChannel, _: *websocket.WsClient, text: []const u8) !void {
        const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, text, .{});
        defer parsed.deinit();

        const root_val = parsed.value;
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse return;
        switch (d_val) {
            .object => |d_obj| {
                const hb_val = d_obj.get("heartbeat_interval") orelse return;
                switch (hb_val) {
                    .integer => |ms| {
                        if (ms > 0) {
                            self.heartbeat_interval_ms.store(@intCast(ms), .release);
                        }
                    },
                    .float => |ms| {
                        if (ms > 0) {
                            self.heartbeat_interval_ms.store(@intFromFloat(ms), .release);
                        }
                    },
                    else => {},
                }
            },
            else => {},
        }
    }

    /// Handle a gateway message, switching on op code.
    fn handleGatewayMessage(self: *DiscordChannel, ws: *websocket.WsClient, text: []const u8) !void {
        const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, text, .{}) catch |err| {
            log.warn("Discord: failed to parse gateway message: {}", .{err});
            return;
        };
        defer parsed.deinit();

        const root_val = parsed.value;
        if (root_val != .object) {
            log.warn("Discord: gateway message root is not an object", .{});
            return;
        }

        // Get op code
        const op_val = root_val.object.get("op") orelse {
            log.warn("Discord: gateway message missing 'op' field", .{});
            return;
        };
        const op: i64 = switch (op_val) {
            .integer => |i| i,
            else => {
                log.warn("Discord: gateway 'op' is not an integer", .{});
                return;
            },
        };

        switch (op) {
            10 => { // HELLO
                self.handleHello(ws, text) catch |err| {
                    log.warn("Discord: handleHello error: {}", .{err});
                };
            },
            0 => { // DISPATCH
                // Update sequence from "s" field
                if (root_val.object.get("s")) |s_val| {
                    switch (s_val) {
                        .integer => |s| {
                            // Sequence comes from the active gateway session and is ordered.
                            // Always overwrite to avoid stale seq after a fresh IDENTIFY.
                            self.sequence.store(s, .release);
                        },
                        else => {},
                    }
                }

                // Get event type "t"
                const t_val = root_val.object.get("t") orelse return;
                const event_type: []const u8 = switch (t_val) {
                    .string => |s| s,
                    else => return,
                };

                log.info("discord gw dispatch t={s} seq={d}", .{ event_type, self.sequence.load(.acquire) });

                if (std.mem.eql(u8, event_type, "READY")) {
                    self.handleReady(root_val) catch |err| {
                        log.warn("Discord: handleReady error: {}", .{err});
                    };
                } else if (std.mem.eql(u8, event_type, "MESSAGE_CREATE")) {
                    self.handleMessageCreate(root_val) catch |err| {
                        log.warn("Discord: handleMessageCreate error: {}", .{err});
                    };
                } else if (std.mem.eql(u8, event_type, "INTERACTION_CREATE")) {
                    self.handleInteractionCreate(root_val) catch |err| {
                        log.warn("Discord: handleInteractionCreate error: {}", .{err});
                    };
                }
            },
            1 => { // HEARTBEAT — server requests immediate heartbeat
                const seq = self.sequence.load(.acquire);
                var hb_buf: [64]u8 = undefined;
                const hb_json = buildHeartbeatJson(&hb_buf, seq) catch return;
                ws.writeText(hb_json) catch |err| {
                    log.warn("Discord: immediate heartbeat failed: {}", .{err});
                };
            },
            11 => { // HEARTBEAT_ACK
                // No-op — heartbeat acknowledged
            },
            7 => { // RECONNECT
                log.info("Discord: server requested reconnect", .{});
                return error.ShouldReconnect;
            },
            9 => { // INVALID_SESSION
                // Check if resumable (d field)
                const d_val = root_val.object.get("d");
                const resumable = if (d_val) |d| switch (d) {
                    .bool => |b| b,
                    else => false,
                } else false;
                switch (self.resolveInvalidSessionAction(resumable)) {
                    .resume_session => {
                        self.sendResumePayload(ws) catch |err| {
                            log.warn("Discord: resume after INVALID_SESSION failed: {}", .{err});
                            return error.ShouldReconnect;
                        };
                    },
                    .identify => {
                        self.sendIdentifyPayload(ws) catch |err| {
                            log.warn("Discord: re-identify after INVALID_SESSION failed: {}", .{err});
                            return error.ShouldReconnect;
                        };
                    },
                }
            },
            else => {
                log.warn("Discord: unhandled gateway op={d}", .{op});
            },
        }
    }

    fn clearSessionStateForIdentify(self: *DiscordChannel) void {
        if (self.session_id) |s| {
            self.allocator.free(s);
            self.session_id = null;
        }
        if (self.resume_gateway_url) |u| {
            self.allocator.free(u);
            self.resume_gateway_url = null;
        }
        self.sequence.store(0, .release);
    }

    fn resolveInvalidSessionAction(self: *DiscordChannel, resumable: bool) InvalidSessionAction {
        if (resumable and self.session_id != null) {
            return .resume_session;
        }
        // Either explicitly non-resumable OR resumable but local session state is absent.
        // In both cases fall back to a clean IDENTIFY path.
        self.clearSessionStateForIdentify();
        return .identify;
    }

    /// Handle READY event: extract session_id, resume_gateway_url, bot_user_id.
    fn handleReady(self: *DiscordChannel, root_val: std.json.Value) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse {
            log.warn("Discord READY: missing 'd' field", .{});
            return;
        };
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => {
                log.warn("Discord READY: 'd' is not an object", .{});
                return;
            },
        };

        // Extract session_id
        if (d_obj.get("session_id")) |sid_val| {
            switch (sid_val) {
                .string => |s| {
                    if (self.session_id) |old| self.allocator.free(old);
                    self.session_id = try self.allocator.dupe(u8, s);
                },
                else => {},
            }
        }

        // Extract resume_gateway_url
        if (d_obj.get("resume_gateway_url")) |rgu_val| {
            switch (rgu_val) {
                .string => |s| {
                    if (self.resume_gateway_url) |old| self.allocator.free(old);
                    self.resume_gateway_url = try self.allocator.dupe(u8, s);
                },
                else => {},
            }
        }

        // Extract bot user ID from d.user.id
        if (d_obj.get("user")) |user_val| {
            switch (user_val) {
                .object => |user_obj| {
                    if (user_obj.get("id")) |id_val| {
                        switch (id_val) {
                            .string => |s| {
                                if (self.bot_user_id) |old| self.allocator.free(old);
                                self.bot_user_id = try self.allocator.dupe(u8, s);
                            },
                            else => {},
                        }
                    }
                },
                else => {},
            }
        }

        log.info("Discord READY: session_id={s}", .{self.session_id orelse "<none>"});
        // A successful READY means we have a live session — reset the reconnect counter
        // so the next op-7 (if any) gets a fresh exponential backoff window.
        self.consecutive_reconnects = 0;
    }

    /// Handle MESSAGE_CREATE event and publish to bus if filters pass.
    fn handleMessageCreate(self: *DiscordChannel, root_val: std.json.Value) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse {
            log.warn("Discord MESSAGE_CREATE: missing 'd' field", .{});
            return;
        };
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'd' is not an object", .{});
                return;
            },
        };

        // Extract channel_id
        const channel_id: []const u8 = if (d_obj.get("channel_id")) |v| switch (v) {
            .string => |s| s,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'channel_id' is not a string", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'channel_id'", .{});
            return;
        };

        // Extract content
        const content: []const u8 = if (d_obj.get("content")) |v| switch (v) {
            .string => |s| s,
            else => "",
        } else "";

        // Extract guild_id (optional — absent for DMs)
        const guild_id: ?[]const u8 = if (d_obj.get("guild_id")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        const message_id: ?[]const u8 = if (d_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        // Extract author object
        const author_obj = if (d_obj.get("author")) |v| switch (v) {
            .object => |o| o,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'author' is not an object", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'author'", .{});
            return;
        };

        // Extract author.id
        const author_id: []const u8 = if (author_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => {
                log.warn("Discord MESSAGE_CREATE: 'author.id' is not a string", .{});
                return;
            },
        } else {
            log.warn("Discord MESSAGE_CREATE: missing 'author.id'", .{});
            return;
        };

        // Extract author.username
        const author_username: ?[]const u8 = if (author_obj.get("username")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        // Extract author.global_name (Discord display name)
        const author_display_name: ?[]const u8 = if (author_obj.get("global_name")) |v| switch (v) {
            .string => |s| if (s.len > 0) s else null,
            else => null,
        } else null;

        // Extract author.bot (defaults to false if absent)
        const author_is_bot: bool = if (author_obj.get("bot")) |v| switch (v) {
            .bool => |b| b,
            else => false,
        } else false;

        // Filter 1: bot author
        if (author_is_bot and !self.allow_bots) {
            log.info("discord gw msg drop: bot author channel={s}", .{channel_id});
            return;
        }

        // Filter 2: require_mention for guild (non-DM) messages
        if (self.require_mention and guild_id != null and !self.isMentionExemptChannel(channel_id)) {
            const bot_uid = self.bot_user_id orelse "";
            if (!isMentioned(content, bot_uid) and !isReplyToBot(d_obj, bot_uid)) {
                log.info("discord gw msg drop: mention required channel={s}", .{channel_id});
                return;
            }
        }

        // Filter 3: allow_from allowlist
        if (!root.isAllowedScoped("discord channel", self.allow_from, author_id)) {
            log.info("discord gw msg drop: allow_from rejected author={s}", .{author_id});
            return;
        }

        // Process attachments (if any)
        var content_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer content_buf.deinit(self.allocator);

        const trimmed_content = std.mem.trim(u8, content, " \t\r\n");
        if (guild_id != null and control_plane.parseSlashCommand(trimmed_content) == null) {
            const speaker = author_display_name orelse author_username orelse author_id;
            content_buf.appendSlice(self.allocator, "[") catch {};
            content_buf.appendSlice(self.allocator, speaker) catch {};
            content_buf.appendSlice(self.allocator, "]: ") catch {};
        }
        if (content.len > 0) {
            content_buf.appendSlice(self.allocator, content) catch {};
        }

        if (d_obj.get("attachments")) |att_val| {
            if (att_val == .array) {
                const rand = std_compat.crypto.random;
                for (att_val.array.items) |att_item| {
                    if (att_item == .object) {
                        if (att_item.object.get("url")) |url_val| {
                            if (url_val == .string) {
                                const attach_url = url_val.string;

                                // Download it
                                if (root.http_util.curlGet(self.allocator, attach_url, &.{}, "30")) |img_data| {
                                    defer self.allocator.free(img_data);

                                    // Make temp file
                                    const rand_id = rand.int(u64);
                                    var path_buf: [1024]u8 = undefined;
                                    const local_path = std.fmt.bufPrint(&path_buf, "/tmp/discord_{x}.dat", .{rand_id}) catch continue;

                                    if (std_compat.fs.createFileAbsolute(local_path, .{ .read = false })) |file| {
                                        file.writeAll(img_data) catch {
                                            file.close();
                                            continue;
                                        };
                                        file.close();

                                        if (content_buf.items.len > 0) content_buf.appendSlice(self.allocator, "\n") catch {};
                                        content_buf.appendSlice(self.allocator, "[IMAGE:") catch {};
                                        content_buf.appendSlice(self.allocator, local_path) catch {};
                                        content_buf.appendSlice(self.allocator, "]") catch {};
                                    } else |_| {}
                                } else |err| {
                                    log.warn("Discord: failed to download attachment: {}", .{err});
                                }
                            }
                        }
                    }
                }
            }
        }

        const final_content = content_buf.toOwnedSlice(self.allocator) catch blk: {
            break :blk try self.allocator.dupe(u8, content);
        };
        defer self.allocator.free(final_content);

        // Build account-aware session key fallback to prevent cross-account bleed
        // when route resolution is unavailable.
        const session_key = if (guild_id == null)
            try std.fmt.allocPrint(self.allocator, "discord:{s}:direct:{s}", .{ self.account_id, author_id })
        else
            try std.fmt.allocPrint(self.allocator, "discord:{s}:channel:{s}", .{ self.account_id, channel_id });
        defer self.allocator.free(session_key);

        var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
        defer metadata_buf.deinit(self.allocator);
        var metadata_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &metadata_buf);
        const mw = &metadata_writer.writer;
        try mw.print("{{\"is_dm\":{s}", .{if (guild_id == null) "true" else "false"});
        try mw.writeAll(",\"account_id\":");
        try root.appendJsonStringW(mw, self.account_id);
        if (guild_id) |gid| {
            try mw.writeAll(",\"guild_id\":");
            try root.appendJsonStringW(mw, gid);
        }
        if (message_id) |mid| {
            try mw.writeAll(",\"message_id\":");
            try root.appendJsonStringW(mw, mid);
        }
        if (self.bot_user_id) |bot_uid| {
            try mw.writeAll(",\"bot_user_id\":");
            try root.appendJsonStringW(mw, bot_uid);
        }
        if (author_username) |uname| {
            try mw.writeAll(",\"sender_username\":");
            try root.appendJsonStringW(mw, uname);
        }
        if (author_display_name) |dname| {
            try mw.writeAll(",\"sender_display_name\":");
            try root.appendJsonStringW(mw, dname);
        }
        try mw.writeByte('}');
        metadata_buf = metadata_writer.toArrayList();

        const msg = try bus_mod.makeInboundFull(
            self.allocator,
            "discord",
            author_id,
            channel_id,
            final_content,
            session_key,
            &.{},
            metadata_buf.items,
        );

        if (self.bus) |b| {
            b.publishInbound(msg) catch |err| {
                log.warn("Discord: failed to publish inbound message: {}", .{err});
                msg.deinit(self.allocator);
                return;
            };
            log.info("discord gw msg published chat={s} bytes={d}", .{ channel_id, final_content.len });
        } else {
            // No bus configured — free the message
            msg.deinit(self.allocator);
        }
    }

    fn handleInteractionCreate(self: *DiscordChannel, root_val: std.json.Value) !void {
        if (root_val != .object) return;
        const d_val = root_val.object.get("d") orelse return;
        const d_obj = switch (d_val) {
            .object => |o| o,
            else => return,
        };

        const interaction_id = if (d_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const interaction_token = if (d_obj.get("token")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const channel_id = if (d_obj.get("channel_id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const interaction_message_id: ?[]const u8 = if (d_obj.get("message")) |v| switch (v) {
            .object => |msg_obj| if (msg_obj.get("id")) |id_val| switch (id_val) {
                .string => |s| s,
                else => null,
            } else null,
            else => null,
        } else null;
        const guild_id: ?[]const u8 = if (d_obj.get("guild_id")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        const data_val = d_obj.get("data") orelse {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported interaction");
            return;
        };
        const data_obj = switch (data_val) {
            .object => |o| o,
            else => {
                self.answerInteraction(interaction_id, interaction_token, "Unsupported interaction");
                return;
            },
        };
        const custom_id = if (data_obj.get("custom_id")) |v| switch (v) {
            .string => |s| s,
            else => {
                self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
                return;
            },
        } else {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
            return;
        };
        const parsed_cb = interaction_choices.parseChoiceCallbackData(custom_id) orelse {
            self.answerInteraction(interaction_id, interaction_token, "Unsupported button");
            return;
        };

        const member_user_obj = if (d_obj.get("member")) |member_val| switch (member_val) {
            .object => |member_obj| if (member_obj.get("user")) |uval| switch (uval) {
                .object => |uobj| uobj,
                else => null,
            } else null,
            else => null,
        } else null;
        const direct_user_obj = if (d_obj.get("user")) |user_val| switch (user_val) {
            .object => |uobj| uobj,
            else => null,
        } else null;
        const user_obj = member_user_obj orelse direct_user_obj orelse {
            self.answerInteraction(interaction_id, interaction_token, "Missing user context");
            return;
        };

        const user_id = if (user_obj.get("id")) |v| switch (v) {
            .string => |s| s,
            else => return,
        } else return;
        const username: ?[]const u8 = if (user_obj.get("username")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;
        const display_name: ?[]const u8 = if (user_obj.get("global_name")) |v| switch (v) {
            .string => |s| s,
            else => null,
        } else null;

        if (!root.isAllowedScoped("discord channel", self.allow_from, user_id)) {
            self.answerInteraction(interaction_id, interaction_token, "You are not allowed to use this button");
            return;
        }

        const selection = try self.consumeCallbackSelection(self.allocator, parsed_cb.token, parsed_cb.option_id, channel_id);
        switch (selection) {
            .ok => |submit_text| {
                defer self.allocator.free(submit_text);
                self.answerInteraction(interaction_id, interaction_token, null);

                const session_key = if (guild_id == null)
                    try std.fmt.allocPrint(self.allocator, "discord:{s}:direct:{s}", .{ self.account_id, user_id })
                else
                    try std.fmt.allocPrint(self.allocator, "discord:{s}:channel:{s}", .{ self.account_id, channel_id });
                defer self.allocator.free(session_key);

                var metadata_buf: std.ArrayListUnmanaged(u8) = .empty;
                defer metadata_buf.deinit(self.allocator);
                var metadata_writer: std.Io.Writer.Allocating = .fromArrayList(self.allocator, &metadata_buf);
                const mw = &metadata_writer.writer;
                try mw.print("{{\"is_dm\":{s}", .{if (guild_id == null) "true" else "false"});
                try mw.writeAll(",\"account_id\":");
                try root.appendJsonStringW(mw, self.account_id);
                try mw.writeAll(",\"interaction\":\"button\"");
                if (std.mem.startsWith(u8, submit_text, "/model ")) {
                    try mw.writeAll(",\"replace_message\":true");
                }
                if (interaction_message_id) |message_id| {
                    try mw.writeAll(",\"message_id\":");
                    try root.appendJsonStringW(mw, message_id);
                }
                if (guild_id) |gid| {
                    try mw.writeAll(",\"guild_id\":");
                    try root.appendJsonStringW(mw, gid);
                }
                if (username) |uname| {
                    try mw.writeAll(",\"sender_username\":");
                    try root.appendJsonStringW(mw, uname);
                }
                if (display_name) |dname| {
                    try mw.writeAll(",\"sender_display_name\":");
                    try root.appendJsonStringW(mw, dname);
                }
                try mw.writeByte('}');
                metadata_buf = metadata_writer.toArrayList();

                const msg = try bus_mod.makeInboundFull(
                    self.allocator,
                    "discord",
                    user_id,
                    channel_id,
                    submit_text,
                    session_key,
                    &.{},
                    metadata_buf.items,
                );
                if (self.bus) |b| {
                    b.publishInbound(msg) catch |err| {
                        log.warn("Discord: failed to publish interaction message: {}", .{err});
                        msg.deinit(self.allocator);
                    };
                } else {
                    msg.deinit(self.allocator);
                }
            },
            .not_found, .expired => self.answerInteraction(interaction_id, interaction_token, "This menu has expired"),
            .invalid_chat => self.answerInteraction(interaction_id, interaction_token, "This button belongs to another chat"),
            .invalid_option => self.answerInteraction(interaction_id, interaction_token, "Unknown button selection"),
        }
    }

    /// Send IDENTIFY payload.
    fn sendIdentifyPayload(self: *DiscordChannel, ws: *websocket.WsClient) !void {
        var buf: [1024]u8 = undefined;
        const json = try buildIdentifyJson(&buf, self.token, self.intents);
        try ws.writeText(json);
    }

    /// Send RESUME payload.
    fn sendResumePayload(self: *DiscordChannel, ws: *websocket.WsClient) !void {
        const sid = self.session_id orelse return error.NoSessionId;
        const seq = self.sequence.load(.acquire);
        var buf: [512]u8 = undefined;
        const json = try buildResumeJson(&buf, self.token, sid, seq);
        try ws.writeText(json);
    }
};

// ════════════════════════════════════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════════════════════════════════════

test "discord send url" {
    var buf: [256]u8 = undefined;
    const url = try DiscordChannel.sendUrl(&buf, "123456");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/123456/messages", url);
}

test "discord typing url" {
    var buf: [256]u8 = undefined;
    const url = try DiscordChannel.typingUrl(&buf, "123456");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/123456/typing", url);
}

test "discord sendTypingIndicator is no-op in tests" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    ch.sendTypingIndicator("123456");
}

test "discord typing handles start empty" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    try std.testing.expect(ch.typing_handles.get("123456") == null);
}

test "discord startTyping stores handle and stopTyping clears it" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    ch.running.store(true, .release);
    defer ch.stopAllTyping();

    try ch.startTyping("123456");
    try std.testing.expect(ch.typing_handles.get("123456") != null);
    std_compat.thread.sleep(50 * std.time.ns_per_ms);
    try ch.stopTyping("123456");
    try std.testing.expect(ch.typing_handles.get("123456") == null);
}

test "discord stopTyping is idempotent" {
    var ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", null, false);
    try ch.stopTyping("123456");
    try ch.stopTyping("123456");
}

test "discord extract bot user id" {
    const id = DiscordChannel.extractBotUserId("MTIzNDU2.Ghijk.abcdef");
    try std.testing.expectEqualStrings("MTIzNDU2", id.?);
}

test "discord extract bot user id no dot" {
    try std.testing.expect(DiscordChannel.extractBotUserId("notokenformat") == null);
}

// ════════════════════════════════════════════════════════════════════════════
// Additional Discord Tests (ported from ZeroClaw Rust)
// ════════════════════════════════════════════════════════════════════════════

test "discord send url with different channel ids" {
    var buf: [256]u8 = undefined;
    const url1 = try DiscordChannel.sendUrl(&buf, "999");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/999/messages", url1);

    var buf2: [256]u8 = undefined;
    const url2 = try DiscordChannel.sendUrl(&buf2, "1234567890");
    try std.testing.expectEqualStrings("https://discord.com/api/v10/channels/1234567890/messages", url2);
}

test "discord extract bot user id multiple dots" {
    // Token format: base64(user_id).timestamp.hmac
    const id = DiscordChannel.extractBotUserId("MTIzNDU2.fake.hmac");
    try std.testing.expectEqualStrings("MTIzNDU2", id.?);
}

test "discord extract bot user id empty token" {
    // Empty string before dot means empty result
    const id = DiscordChannel.extractBotUserId("");
    try std.testing.expect(id == null);
}

test "discord extract bot user id single dot" {
    const id = DiscordChannel.extractBotUserId("abc.");
    try std.testing.expectEqualStrings("abc", id.?);
}

test "discord max message len constant" {
    try std.testing.expectEqual(@as(usize, 2000), DiscordChannel.MAX_MESSAGE_LEN);
}

test "discord gateway url constant" {
    try std.testing.expectEqualStrings("wss://gateway.discord.gg/?v=10&encoding=json", DiscordChannel.GATEWAY_URL);
}

test "discord init stores fields" {
    const ch = DiscordChannel.init(std.testing.allocator, "my-bot-token", "guild-123", true);
    try std.testing.expectEqualStrings("my-bot-token", ch.token);
    try std.testing.expectEqualStrings("guild-123", ch.guild_id.?);
    try std.testing.expect(ch.allow_bots);
}

test "discord init no guild id" {
    const ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expect(ch.guild_id == null);
    try std.testing.expect(!ch.allow_bots);
}

test "discord send url buffer too small returns error" {
    var buf: [10]u8 = undefined;
    const result = DiscordChannel.sendUrl(&buf, "123456");
    try std.testing.expect(if (result) |_| false else |_| true);
}

// ════════════════════════════════════════════════════════════════════════════
// New Gateway Helper Tests
// ════════════════════════════════════════════════════════════════════════════

test "discord buildIdentifyJson" {
    var buf: [512]u8 = undefined;
    const json = try DiscordChannel.buildIdentifyJson(&buf, "mytoken", 37377);
    // Should contain op:2 and the token and intents
    try std.testing.expect(std.mem.indexOf(u8, json, "\"op\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "mytoken") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "37377") != null);
}

test "discord buildHeartbeatJson no sequence" {
    var buf: [64]u8 = undefined;
    const json = try DiscordChannel.buildHeartbeatJson(&buf, 0);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":null}", json);
}

test "discord buildHeartbeatJson with sequence" {
    var buf: [64]u8 = undefined;
    const json = try DiscordChannel.buildHeartbeatJson(&buf, 42);
    try std.testing.expectEqualStrings("{\"op\":1,\"d\":42}", json);
}

test "discord buildResumeJson" {
    var buf: [256]u8 = undefined;
    const json = try DiscordChannel.buildResumeJson(&buf, "mytoken", "session123", 99);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"op\":6") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "session123") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "99") != null);
}

test "discord parseGatewayHost from wss url" {
    const host = DiscordChannel.parseGatewayHost("wss://us-east1.gateway.discord.gg");
    try std.testing.expectEqualStrings("us-east1.gateway.discord.gg", host);
}

test "discord parseGatewayHost with path" {
    const host = DiscordChannel.parseGatewayHost("wss://gateway.discord.gg/?v=10&encoding=json");
    try std.testing.expectEqualStrings("gateway.discord.gg", host);
}

test "discord parseGatewayHost no scheme returns original" {
    const host = DiscordChannel.parseGatewayHost("gateway.discord.gg");
    try std.testing.expectEqualStrings("gateway.discord.gg", host);
}

test "discord isMentioned with user id" {
    try std.testing.expect(DiscordChannel.isMentioned("<@123456> hello", "123456"));
    try std.testing.expect(DiscordChannel.isMentioned("hello <@!123456>", "123456"));
    try std.testing.expect(!DiscordChannel.isMentioned("hello world", "123456"));
    try std.testing.expect(!DiscordChannel.isMentioned("<@999999> hello", "123456"));
}

test "discord intents default" {
    const ch = DiscordChannel.init(std.testing.allocator, "tok", null, false);
    try std.testing.expectEqual(@as(u32, 37377), ch.intents);
}

test "discord initFromConfig passes all fields" {
    const config_types = @import("../config_types.zig");
    const cfg = config_types.DiscordConfig{
        .account_id = "discord-main",
        .token = "my-token",
        .guild_id = "guild-1",
        .allow_bots = true,
        .allow_from = &.{ "user1", "user2" },
        .require_mention = true,
        .intents = 512,
    };
    const ch = DiscordChannel.initFromConfig(std.testing.allocator, cfg);
    try std.testing.expectEqualStrings("my-token", ch.token);
    try std.testing.expectEqualStrings("guild-1", ch.guild_id.?);
    try std.testing.expect(ch.allow_bots);
    try std.testing.expectEqualStrings("discord-main", ch.account_id);
    try std.testing.expectEqual(@as(usize, 2), ch.allow_from.len);
    try std.testing.expect(ch.require_mention);
    try std.testing.expectEqual(@as(u32, 512), ch.intents);
}

test "discord buildComponentsJson packs sixth option into final row" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);

    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "m1", .label = "One", .submit_text = "/model one" },
        .{ .id = "m2", .label = "Two", .submit_text = "/model two" },
        .{ .id = "m3", .label = "Three", .submit_text = "/model three" },
        .{ .id = "m4", .label = "Four", .submit_text = "/model four" },
        .{ .id = "prev", .label = "Prev", .submit_text = "/model page 1" },
        .{ .id = "next", .label = "Next", .submit_text = "/model page 3" },
    };
    var directive = try ch.buildChoicesDirectiveFromPayload(&choices);
    defer directive.deinit(alloc);

    const json = try ch.buildComponentsJson(directive, "abc");
    defer alloc.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:m1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:prev\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"custom_id\":\"nc1:abc:next\"") != null);
}

test "discord handleMessageCreate publishes inbound guild message with metadata" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .allow_from = &.{"u-1"},
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"c-1","guild_id":"g-1","content":"hello","author":{"id":"u-1","username":"discord-user","global_name":"Discord User","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord", msg.channel);
    try std.testing.expectEqualStrings("u-1", msg.sender_id);
    try std.testing.expectEqualStrings("c-1", msg.chat_id);
    try std.testing.expectEqualStrings("[Discord User]: hello", msg.content);
    try std.testing.expectEqualStrings("discord:dc-main:channel:c-1", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expect(meta.value.object.get("account_id") != null);
    try std.testing.expect(meta.value.object.get("is_dm") != null);
    try std.testing.expect(meta.value.object.get("guild_id") != null);
    try std.testing.expect(meta.value.object.get("sender_username") != null);
    try std.testing.expect(meta.value.object.get("sender_display_name") != null);
    try std.testing.expectEqualStrings("dc-main", meta.value.object.get("account_id").?.string);
    try std.testing.expect(!meta.value.object.get("is_dm").?.bool);
    try std.testing.expectEqualStrings("g-1", meta.value.object.get("guild_id").?.string);
    try std.testing.expectEqualStrings("discord-user", meta.value.object.get("sender_username").?.string);
    try std.testing.expectEqualStrings("Discord User", meta.value.object.get("sender_display_name").?.string);
}

test "discord handleMessageCreate empty allow_from denies inbound message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"c-1","guild_id":"g-1","content":"hello","author":{"id":"u-1","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord handleMessageCreate wildcard allow_from permits inbound message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .allow_from = &.{"*"},
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"c-1","guild_id":"g-1","content":"hello","author":{"id":"u-1","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 1), event_bus.inboundDepth());
    var msg = event_bus.consumeInbound().?;
    defer msg.deinit(alloc);
}

test "discord handleInteractionCreate publishes synthetic inbound command" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .allow_from = &.{"u-9"},
    });
    ch.setBus(&event_bus);
    defer ch.deinitPendingInteractions();

    const choices = [_]root.Channel.OutboundChoice{
        .{ .id = "m1", .label = "Alpha", .submit_text = "/model alpha" },
        .{ .id = "next", .label = "Next", .submit_text = "/model page 2" },
    };
    var directive = try ch.buildChoicesDirectiveFromPayload(&choices);
    defer directive.deinit(alloc);
    try ch.registerPendingInteraction("tok1", "c-9", directive);

    const interaction_json =
        \\{"d":{"id":"i-1","token":"itok","channel_id":"c-9","guild_id":"g-9","member":{"user":{"id":"u-9","username":"discord-user","global_name":"Discord User"}},"data":{"custom_id":"nc1:tok1:m1"}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, interaction_json, .{});
    defer parsed.deinit();

    try ch.handleInteractionCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord", msg.channel);
    try std.testing.expectEqualStrings("u-9", msg.sender_id);
    try std.testing.expectEqualStrings("c-9", msg.chat_id);
    try std.testing.expectEqualStrings("/model alpha", msg.content);
    try std.testing.expectEqualStrings("discord:dc-main:channel:c-9", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"interaction\":\"button\"") != null);
}

test "discord handleMessageCreate sets is_dm metadata for direct messages" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .allow_from = &.{"u-7"},
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"channel_id":"dm-7","content":"hi dm","author":{"id":"u-7","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("discord:dc-main:direct:u-7", msg.session_key);
    try std.testing.expect(msg.metadata_json != null);

    const meta = try std.json.parseFromSlice(std.json.Value, alloc, msg.metadata_json.?, .{});
    defer meta.deinit();
    try std.testing.expect(meta.value == .object);
    try std.testing.expect(meta.value.object.get("is_dm") != null);
    try std.testing.expect(meta.value.object.get("is_dm").?.bool);
    try std.testing.expect(meta.value.object.get("guild_id") == null);
}

test "discord handleMessageCreate require_mention blocks unmentioned guild messages" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
        .allow_from = &.{"u-2"},
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","content":"plain text","author":{"id":"u-2","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord natural channel bypasses mention gate and preserves speaker" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
        .mention_exempt_channels = &.{"natural-1"},
        .allow_from = &.{"u-2"},
    });
    ch.setBus(&event_bus);

    const msg_json =
        \\{"d":{"id":"msg-42","channel_id":"natural-1","guild_id":"g-2","content":"plain text","author":{"id":"u-2","username":"alice","global_name":"Alice","bot":false}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    var msg = event_bus.consumeInbound() orelse return error.TestUnexpectedResult;
    defer msg.deinit(alloc);
    try std.testing.expectEqualStrings("[Alice]: plain text", msg.content);
    try std.testing.expect(std.mem.indexOf(u8, msg.metadata_json.?, "\"message_id\":\"msg-42\"") != null);
}

test "discord outbound parser extracts local files and preserves remote media as links" {
    const alloc = std.testing.allocator;
    const media = [_][]const u8{"https://example.com/report.pdf"};
    const parsed = try DiscordChannel.parseOutboundMessage(
        alloc,
        "result\n[IMAGE:/tmp/chart.png]",
        &media,
    );
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("result\nhttps://example.com/report.pdf", parsed.text);
    try std.testing.expectEqual(@as(usize, 1), parsed.files.len);
    try std.testing.expectEqualStrings("/tmp/chart.png", parsed.files[0]);
}

test "discord outbound parser accepts brackets in attachment paths" {
    const alloc = std.testing.allocator;
    const parsed = try DiscordChannel.parseOutboundMessage(alloc, "[IMAGE:/tmp/chart[1].png]", &.{});
    defer parsed.deinit(alloc);

    try std.testing.expectEqualStrings("", parsed.text);
    try std.testing.expectEqual(@as(usize, 1), parsed.files.len);
    try std.testing.expectEqualStrings("/tmp/chart[1].png", parsed.files[0]);
}

test "discord handleMessageCreate require_mention accepts reply to bot message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
        .allow_from = &.{"u-2"},
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":19,"content":"reply text","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"bot-1","bot":true}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 1), event_bus.inboundDepth());

    var msg = event_bus.consumeInbound() orelse return try std.testing.expect(false);
    defer msg.deinit(alloc);
}

test "discord handleMessageCreate require_mention still blocks reply to non-bot message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":19,"content":"reply text","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"other-user","bot":false}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord handleMessageCreate require_mention ignores non-reply references to bot message" {
    const alloc = std.testing.allocator;
    var event_bus = bus_mod.Bus.init();
    defer event_bus.close();

    var ch = DiscordChannel.initFromConfig(alloc, .{
        .account_id = "dc-main",
        .token = "token",
        .require_mention = true,
    });
    ch.setBus(&event_bus);
    ch.bot_user_id = try alloc.dupe(u8, "bot-1");
    defer alloc.free(ch.bot_user_id.?);

    const msg_json =
        \\{"d":{"channel_id":"c-2","guild_id":"g-2","type":21,"content":"","author":{"id":"u-2","bot":false},"referenced_message":{"author":{"id":"bot-1","bot":true}}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, alloc, msg_json, .{});
    defer parsed.deinit();

    try ch.handleMessageCreate(parsed.value);
    try std.testing.expectEqual(@as(usize, 0), event_bus.inboundDepth());
}

test "discord dispatch sequence accepts lower values after session reset" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    defer {
        if (ch.session_id) |s| std.testing.allocator.free(s);
        if (ch.resume_gateway_url) |u| std.testing.allocator.free(u);
        if (ch.bot_user_id) |u| std.testing.allocator.free(u);
    }

    // Simulate stale sequence from an old session.
    ch.sequence.store(42, .release);

    var ws_dummy: websocket.WsClient = undefined;
    const ready_dispatch =
        \\{"op":0,"s":1,"t":"READY","d":{"session_id":"sess-1","resume_gateway_url":"wss://gateway.discord.gg/?v=10&encoding=json","user":{"id":"bot-1"}}}
    ;
    try ch.handleGatewayMessage(&ws_dummy, ready_dispatch);

    try std.testing.expectEqual(@as(i64, 1), ch.sequence.load(.acquire));
}

test "discord invalid session non-resumable clears state and identifies" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.session_id = try alloc.dupe(u8, "sess-1");
    ch.resume_gateway_url = try alloc.dupe(u8, "wss://gateway.discord.gg/?v=10&encoding=json");
    ch.sequence.store(77, .release);

    const action = ch.resolveInvalidSessionAction(false);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.identify, action);
    try std.testing.expect(ch.session_id == null);
    try std.testing.expect(ch.resume_gateway_url == null);
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
}

test "discord invalid session resumable keeps state and resumes" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.session_id = try alloc.dupe(u8, "sess-2");
    defer {
        if (ch.session_id) |s| alloc.free(s);
    }
    ch.sequence.store(123, .release);

    const action = ch.resolveInvalidSessionAction(true);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.resume_session, action);
    try std.testing.expect(ch.session_id != null);
    try std.testing.expectEqual(@as(i64, 123), ch.sequence.load(.acquire));
}

test "discord invalid session resumable without session falls back to identify" {
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.resume_gateway_url = try alloc.dupe(u8, "wss://gateway.discord.gg/?v=10&encoding=json");
    ch.sequence.store(33, .release);

    const action = ch.resolveInvalidSessionAction(true);
    try std.testing.expectEqual(DiscordChannel.InvalidSessionAction.identify, action);
    try std.testing.expect(ch.session_id == null);
    try std.testing.expect(ch.resume_gateway_url == null);
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
}

test "discord intent bitmask guilds" {
    // GUILDS = 1
    try std.testing.expectEqual(@as(u32, 1), 1);
    // GUILD_MESSAGES = 512
    try std.testing.expectEqual(@as(u32, 512), 512);
    // MESSAGE_CONTENT = 32768
    try std.testing.expectEqual(@as(u32, 32768), 32768);
    // DIRECT_MESSAGES = 4096
    try std.testing.expectEqual(@as(u32, 4096), 4096);
    // Default intents = 1|512|32768|4096 = 37377
    try std.testing.expectEqual(@as(u32, 37377), 1 | 512 | 32768 | 4096);
}

test "DiscordChannel create + healthCheck + stop leaks zero bytes" {
    // DiscordChannel holds no heap allocations at init-time.  No deinit needed.
    var ch_struct = DiscordChannel.initFromConfig(std.testing.allocator, .{
        .token = "test-bot-token",
    });

    const ch = ch_struct.channel();
    _ = ch.healthCheck();
    ch.stop();
}

test "discord health check tolerates expected heartbeat idle window" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    ch.running.store(true, .release);
    ch.heartbeat_interval_ms.store(40_000, .release);
    ch.last_gateway_activity_ms.store(1_000_000, .release);

    // Within 3× heartbeat window (120s) — must still be healthy.
    try std.testing.expect(ch.gatewayHealthyAt(1_119_999));
}

test "discord health check fails after stale gateway idle" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    ch.running.store(true, .release);
    ch.heartbeat_interval_ms.store(40_000, .release);
    // Regression: a node could stay Discord-online while the gateway socket stopped
    // delivering events — heartbeat ACKs ceased but the process didn't restart.
    ch.last_gateway_activity_ms.store(1_000_000, .release);

    // Past 3× heartbeat window (120s) — must be stale.
    try std.testing.expect(!ch.gatewayHealthyAt(1_120_001));
}

test "discord gateway restart refreshes stale activity baseline" {
    var ch = DiscordChannel.init(std.testing.allocator, "token", null, false);
    ch.running.store(true, .release);
    ch.heartbeat_interval_ms.store(40_000, .release);
    ch.last_gateway_activity_ms.store(1_000_000, .release);
    try std.testing.expect(!ch.gatewayHealthyAt(1_120_001));

    // Regression: after the watchdog restarts the gateway, the next connection
    // attempt must not inherit the stale socket timestamp and immediately fail
    // health checks before DNS/TCP/TLS has its own grace window.
    ch.last_gateway_activity_ms.store(1_120_001, .release);
    try std.testing.expect(ch.gatewayHealthyAt(1_130_001));
    try std.testing.expect(!ch.gatewayHealthyAt(1_240_002));
}

test "discord handleReady resets consecutive_reconnects to zero" {
    // Regression: rapid op-7 reconnect storms; READY must reset the backoff counter.
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    defer {
        if (ch.session_id) |s| alloc.free(s);
        if (ch.resume_gateway_url) |u| alloc.free(u);
        if (ch.bot_user_id) |u| alloc.free(u);
    }
    ch.consecutive_reconnects = 3;

    const ready_json =
        \\{"op":0,"s":1,"t":"READY","d":{"session_id":"sess-rc","resume_gateway_url":"wss://gateway.discord.gg/?v=10&encoding=json","user":{"id":"bot-rc"}}}
    ;
    var ws_dummy: websocket.WsClient = undefined;
    try ch.handleGatewayMessage(&ws_dummy, ready_json);

    try std.testing.expectEqual(@as(u32, 0), ch.consecutive_reconnects);
}

test "discord reconnect backoff clears session on exhaustion" {
    // Regression: after MAX_RECONNECT_ATTEMPTS consecutive op-7s the session must be
    // cleared so the next attempt does a fresh IDENTIFY rather than looping forever.
    const alloc = std.testing.allocator;
    var ch = DiscordChannel.init(alloc, "token", null, false);
    ch.session_id = try alloc.dupe(u8, "stale-sess");
    ch.resume_gateway_url = try alloc.dupe(u8, "wss://gateway.discord.gg/?v=10&encoding=json");
    ch.sequence.store(99, .release);
    ch.consecutive_reconnects = DiscordChannel.MAX_RECONNECT_ATTEMPTS - 1;

    const reconnect = ch.recordReconnectRequest();

    try std.testing.expectEqual(DiscordChannel.MAX_RECONNECT_ATTEMPTS, reconnect.attempt);
    try std.testing.expectEqual(@as(u64, 16_000), reconnect.backoff_ms);
    try std.testing.expect(reconnect.cleared_session);
    try std.testing.expect(ch.session_id == null);
    try std.testing.expect(ch.resume_gateway_url == null);
    try std.testing.expectEqual(@as(i64, 0), ch.sequence.load(.acquire));
    try std.testing.expectEqual(@as(u32, 0), ch.consecutive_reconnects);
}
