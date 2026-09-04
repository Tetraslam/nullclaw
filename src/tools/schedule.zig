const std = @import("std");
const root = @import("root.zig");
const Tool = root.Tool;
const ToolResult = root.ToolResult;
const JsonObjectMap = root.JsonObjectMap;
const cron = @import("../cron.zig");
const CronScheduler = cron.CronScheduler;
const agent_routing = @import("../agent_routing.zig");
const security_policy = @import("../security/policy.zig");
const cron_gateway = @import("cron_gateway.zig");
const loadScheduler = @import("cron_add.zig").loadScheduler;

threadlocal var tls_schedule_channel: ?[]const u8 = null;
threadlocal var tls_schedule_account_id: ?[]const u8 = null;
threadlocal var tls_schedule_chat_id: ?[]const u8 = null;
threadlocal var tls_schedule_peer_kind: ?agent_routing.ChatType = null;
threadlocal var tls_schedule_peer_id: ?[]const u8 = null;
threadlocal var tls_schedule_thread_id: ?[]const u8 = null;
threadlocal var tls_schedule_local_store = false;
threadlocal var tls_schedule_disabled = false;
threadlocal var tls_schedule_max_tasks: ?usize = null;
threadlocal var tls_schedule_shell_policy: ?security_policy.SecurityPolicy = null;

pub fn setSchedulerCapabilities(local_store: bool, disabled: bool, max_tasks: ?usize, shell_policy: ?security_policy.SecurityPolicy) void {
    tls_schedule_local_store = local_store;
    tls_schedule_disabled = disabled;
    tls_schedule_max_tasks = if (local_store) max_tasks else null;
    tls_schedule_shell_policy = if (local_store) shell_policy else null;
}

pub fn clearSchedulerCapabilities() void {
    tls_schedule_local_store = false;
    tls_schedule_disabled = false;
    tls_schedule_max_tasks = null;
    tls_schedule_shell_policy = null;
}

/// Schedule tool — lets the agent manage recurring and one-shot scheduled tasks.
/// Delegates to the CronScheduler from the cron module for persistent job management.
pub const ScheduleTool = struct {
    pub const tool_name = "schedule";
    pub const tool_description = "Manage scheduled tasks. Actions: create/add/once/list/get/update/cancel/remove/pause/resume. Use 'command' for shell jobs or 'prompt' (with optional 'model') for agent jobs. For a durable watcher, use action='once', prompt, delay, and repeat_delay; the scheduler rearms it until the agent returns a terminal WATCHER marker. Optional delivery params: channel, account_id, chat_id. Set session_target to 'main' for agent jobs to route results through the main agent.";
    pub const tool_params =
        \\{"type":"object","properties":{"action":{"type":"string","enum":["create","add","once","list","get","update","cancel","remove","pause","resume"],"description":"Action to perform"},"expression":{"type":"string","description":"Cron expression for recurring tasks"},"delay":{"type":"string","description":"Delay for one-shot tasks (e.g. '30m', '2h')"},"repeat_delay":{"type":"string","description":"Positive delay between watcher checks; valid when creating or updating a watcher (e.g. '5m')"},"command":{"type":"string","description":"Shell command to execute"},"prompt":{"type":"string","description":"Prompt for an agent job"},"model":{"type":"string","description":"Model override for an agent job"},"enabled":{"type":"boolean","description":"Enable or disable a job during update"},"id":{"type":"string","description":"Task ID"},"channel":{"type":"string","description":"Delivery channel for notifications (e.g. telegram, signal, matrix)"},"account_id":{"type":"string","description":"Optional channel account ID for multi-account routing"},"chat_id":{"type":"string","description":"Chat ID for delivery notification"},"session_target":{"type":"string","enum":["isolated","main"],"description":"Routing mode for agent job delivery"}},"required":["action"]}
    ;

    const vtable = root.ToolVTable(@This());

    /// Set the context for the current turn (called before agent.turn).
    pub fn setContext(
        self: *ScheduleTool,
        channel: ?[]const u8,
        account_id: ?[]const u8,
        chat_id: ?[]const u8,
        peer_kind: ?agent_routing.ChatType,
        peer_id: ?[]const u8,
        thread_id: ?[]const u8,
    ) void {
        _ = self;
        tls_schedule_channel = channel;
        tls_schedule_account_id = account_id;
        tls_schedule_chat_id = chat_id;
        tls_schedule_peer_kind = peer_kind;
        tls_schedule_peer_id = peer_id;
        tls_schedule_thread_id = thread_id;
    }

    pub fn tool(self: *ScheduleTool) Tool {
        return .{
            .ptr = @ptrCast(self),
            .vtable = &vtable,
        };
    }

    pub fn execute(self: *ScheduleTool, allocator: std.mem.Allocator, args: JsonObjectMap) !ToolResult {
        _ = self;
        if (tls_schedule_disabled) return ToolResult.fail("The schedule tool is disabled for this agent run");
        const action = stringArg(args, "action") orelse return ToolResult.fail("Missing 'action' parameter");
        if (args.get("repeat_delay")) |value| {
            if (value != .string and value != .null) return ToolResult.fail("Invalid 'repeat_delay': expected a positive duration string");
        }
        const repeat_delay = stringArg(args, "repeat_delay");
        var repeat_delay_secs: ?i64 = null;
        if (repeat_delay) |value| {
            const creates_watcher = std.mem.eql(u8, action, "once") and stringArg(args, "prompt") != null and stringArg(args, "command") == null;
            if (!creates_watcher and !std.mem.eql(u8, action, "update")) {
                return ToolResult.fail("'repeat_delay' is only supported when creating or updating a watcher");
            }
            repeat_delay_secs = cron.parseDuration(value) catch
                return ToolResult.fail("Invalid 'repeat_delay': expected a positive duration string");
        }
        const explicit_channel = stringArg(args, "channel");
        const explicit_account_id = stringArg(args, "account_id");
        const explicit_chat_id = stringArg(args, "chat_id");
        const session_target = if (stringArg(args, "session_target")) |value|
            cron.SessionTarget.parseStrict(value) catch
                return ToolResult.fail("Invalid 'session_target' parameter: expected 'isolated' or 'main'")
        else
            cron.SessionTarget.isolated;

        const chat_id = explicit_chat_id orelse tls_schedule_chat_id;
        const delivery_channel = explicit_channel orelse tls_schedule_channel orelse "telegram";
        const delivery_account_id = explicit_account_id orelse tls_schedule_account_id;
        if (explicit_channel) |channel| {
            if (explicit_chat_id == null and tls_schedule_chat_id != null) {
                if (tls_schedule_channel) |current_channel| {
                    if (!std.mem.eql(u8, channel, current_channel)) {
                        return ToolResult.fail("When overriding 'channel', also provide 'chat_id' for the target conversation");
                    }
                }
            }
        }

        const context_routing_allowed = explicit_channel == null and explicit_account_id == null and explicit_chat_id == null;
        const delivery = if (chat_id) |target|
            cron.enrichDeliveryRouting(cron.DeliveryConfig{
                .mode = .always,
                .channel = delivery_channel,
                .account_id = delivery_account_id,
                .to = target,
                .peer_kind = if (context_routing_allowed) tls_schedule_peer_kind else null,
                .peer_id = if (context_routing_allowed) tls_schedule_peer_id else null,
                .thread_id = if (context_routing_allowed) tls_schedule_thread_id else null,
            })
        else
            cron.DeliveryConfig{};

        var live = cron.lockLiveScheduler();
        defer live.deinit();
        if (live.scheduler) |scheduler| {
            return executeWithScheduler(allocator, args, scheduler, action, session_target, delivery, repeat_delay_secs);
        }

        live.deinit();
        if (!tls_schedule_local_store) {
            if (try executeViaGateway(allocator, args, action, session_target, delivery, repeat_delay)) |result| return result;
        }

        var scheduler = if (tls_schedule_max_tasks) |max_tasks|
            loadSchedulerWithMaxTasks(allocator, max_tasks) catch return ToolResult.fail("Failed to load scheduler state")
        else
            loadScheduler(allocator) catch return ToolResult.fail("Failed to load scheduler state");
        defer scheduler.deinit();
        return executeWithScheduler(allocator, args, &scheduler, action, session_target, delivery, repeat_delay_secs);
    }
};

fn loadSchedulerWithMaxTasks(allocator: std.mem.Allocator, max_tasks: usize) !CronScheduler {
    var scheduler = CronScheduler.init(allocator, max_tasks, true);
    if (tls_schedule_shell_policy) |policy| scheduler.setShellPolicy(policy);
    cron.loadJobs(&scheduler) catch {};
    return scheduler;
}

fn stringArg(args: JsonObjectMap, key: []const u8) ?[]const u8 {
    const value = root.getString(args, key) orelse return null;
    if (std.mem.trim(u8, value, " \t\r\n").len == 0) return null;
    return value;
}

fn mutationFailure(allocator: std.mem.Allocator, operation: []const u8, err: anyerror) !ToolResult {
    const msg = try std.fmt.allocPrint(allocator, "Failed to {s}: {s}", .{ operation, @errorName(err) });
    return .{ .success = false, .output = "", .error_msg = msg };
}

fn gatewayResult(resp: anytype) ToolResult {
    if (resp.status_code >= 200 and resp.status_code < 300) {
        return .{ .success = true, .output = resp.body };
    }
    return .{ .success = false, .output = "", .error_msg = resp.body };
}

fn executeViaGateway(
    allocator: std.mem.Allocator,
    args: JsonObjectMap,
    action: []const u8,
    session_target: cron.SessionTarget,
    delivery: cron.DeliveryConfig,
    repeat_delay: ?[]const u8,
) !?ToolResult {
    if (std.mem.eql(u8, action, "list")) {
        return switch (cron.requestGatewayGet(allocator, "/cron")) {
            .unavailable => null,
            .response => |resp| gatewayResult(resp),
        };
    }

    if (std.mem.eql(u8, action, "get")) {
        const id = stringArg(args, "id") orelse return ToolResult.fail("Missing 'id' parameter for get action");
        return switch (cron.requestGatewayGet(allocator, "/cron")) {
            .unavailable => null,
            .response => |resp| blk: {
                if (resp.status_code < 200 or resp.status_code >= 300) break :blk gatewayResult(resp);
                defer allocator.free(resp.body);
                const job_json = cron_gateway.findJobByIdJson(allocator, resp.body, id) catch
                    return ToolResult.fail("Invalid gateway response");
                if (job_json) |json| break :blk ToolResult{ .success = true, .output = json };
                const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
                break :blk ToolResult{ .success = false, .output = "", .error_msg = msg };
            },
        };
    }

    if (std.mem.eql(u8, action, "create") or std.mem.eql(u8, action, "add") or std.mem.eql(u8, action, "once")) {
        const command = stringArg(args, "command");
        const prompt = stringArg(args, "prompt");
        const model = stringArg(args, "model");
        if (command == null and prompt == null) return ToolResult.fail("Missing 'command' or 'prompt' parameter");
        if (command != null and prompt != null) return ToolResult.fail("Provide either 'command' or 'prompt', not both");
        if (prompt == null and session_target != .isolated) {
            return ToolResult.fail("session_target is only supported for agent jobs created with 'prompt'");
        }

        const one_shot = std.mem.eql(u8, action, "once");
        const expression = if (one_shot) null else stringArg(args, "expression") orelse
            return ToolResult.fail("Missing 'expression' parameter for cron job");
        const delay = if (one_shot) stringArg(args, "delay") orelse
            return ToolResult.fail("Missing 'delay' parameter for one-shot task") else null;
        const gateway_body = cron_gateway.buildAddBody(
            allocator,
            expression,
            delay,
            repeat_delay,
            command,
            prompt,
            model,
            if (delivery.to != null) delivery else null,
            if (prompt != null) session_target else null,
        ) catch return null;
        defer allocator.free(gateway_body);
        return switch (cron.requestGatewayPost(allocator, "/cron/add", gateway_body)) {
            .unavailable => null,
            .response => |resp| gatewayResult(resp),
        };
    }

    if (std.mem.eql(u8, action, "update")) {
        const id = stringArg(args, "id") orelse return ToolResult.fail("Missing 'id' parameter for update action");
        const expression = stringArg(args, "expression");
        const command = stringArg(args, "command");
        const prompt = stringArg(args, "prompt");
        const model = stringArg(args, "model");
        const enabled = root.getBool(args, "enabled");
        const target = if (stringArg(args, "session_target")) |value|
            cron.SessionTarget.parseStrict(value) catch
                return ToolResult.fail("Invalid 'session_target' parameter: expected 'isolated' or 'main'")
        else
            null;
        if (expression == null and command == null and prompt == null and model == null and enabled == null and target == null and repeat_delay == null) {
            return ToolResult.fail("Nothing to update");
        }
        const gateway_body = cron_gateway.buildUpdateBody(allocator, id, expression, command, prompt, model, enabled, target, repeat_delay) catch return null;
        defer allocator.free(gateway_body);
        return switch (cron.requestGatewayPost(allocator, "/cron/update", gateway_body)) {
            .unavailable => null,
            .response => |resp| gatewayResult(resp),
        };
    }

    if (std.mem.eql(u8, action, "cancel") or std.mem.eql(u8, action, "remove") or
        std.mem.eql(u8, action, "pause") or std.mem.eql(u8, action, "resume"))
    {
        const id = stringArg(args, "id") orelse return ToolResult.fail(if (std.mem.eql(u8, action, "cancel") or std.mem.eql(u8, action, "remove"))
            "Missing 'id' parameter for cancel action"
        else
            "Missing 'id' parameter");
        const gateway_body = cron_gateway.buildIdBody(allocator, id) catch return null;
        defer allocator.free(gateway_body);
        const path = if (std.mem.eql(u8, action, "pause"))
            "/cron/pause"
        else if (std.mem.eql(u8, action, "resume"))
            "/cron/resume"
        else
            "/cron/remove";
        return switch (cron.requestGatewayPost(allocator, path, gateway_body)) {
            .unavailable => null,
            .response => |resp| gatewayResult(resp),
        };
    }

    return null;
}

fn executeWithScheduler(
    allocator: std.mem.Allocator,
    args: JsonObjectMap,
    scheduler: *CronScheduler,
    action: []const u8,
    session_target: cron.SessionTarget,
    delivery: cron.DeliveryConfig,
    repeat_delay_secs: ?i64,
) !ToolResult {
    if (std.mem.eql(u8, action, "list")) {
        const jobs = scheduler.listJobs();
        if (jobs.len == 0) return .{ .success = true, .output = try allocator.dupe(u8, "No scheduled jobs.") };

        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(allocator);
        try buf.print(allocator, "Scheduled jobs ({d}):\n", .{jobs.len});
        for (jobs) |job| {
            const flags: []const u8 = if (job.paused and job.isWatcher())
                " [paused, watcher]"
            else if (job.isWatcher())
                " [watcher]"
            else if (job.paused and job.one_shot)
                " [paused, one-shot]"
            else if (job.paused)
                " [paused]"
            else if (job.one_shot)
                " [one-shot]"
            else
                "";
            if (job.isWatcher()) {
                try buf.print(allocator, "- {s} | {s} | status={s}{s} | repeat_delay_secs={d} | cmd: {s}\n", .{
                    job.id,
                    job.expression,
                    job.last_status orelse "pending",
                    flags,
                    job.repeat_delay_secs.?,
                    job.command,
                });
            } else {
                try buf.print(allocator, "- {s} | {s} | status={s}{s} | cmd: {s}\n", .{
                    job.id,
                    job.expression,
                    job.last_status orelse "pending",
                    flags,
                    job.command,
                });
            }
        }
        return .{ .success = true, .output = try buf.toOwnedSlice(allocator) };
    }

    if (std.mem.eql(u8, action, "get")) {
        const id = stringArg(args, "id") orelse return ToolResult.fail("Missing 'id' parameter for get action");
        const job = scheduler.getJob(id) orelse {
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
            return .{ .success = false, .output = "", .error_msg = msg };
        };
        const flags: []const u8 = if (job.paused and job.isWatcher())
            " [paused, watcher]"
        else if (job.isWatcher())
            " [watcher]"
        else if (job.paused and job.one_shot)
            " [paused, one-shot]"
        else if (job.paused)
            " [paused]"
        else if (job.one_shot)
            " [one-shot]"
        else
            "";
        const msg = if (job.isWatcher())
            try std.fmt.allocPrint(allocator, "Job {s} | {s} | next={d} | status={s}{s} | repeat_delay_secs={d}\n  cmd: {s}", .{
                job.id,
                job.expression,
                job.next_run_secs,
                job.last_status orelse "pending",
                flags,
                job.repeat_delay_secs.?,
                job.command,
            })
        else
            try std.fmt.allocPrint(allocator, "Job {s} | {s} | next={d} | status={s}{s}\n  cmd: {s}", .{
                job.id,
                job.expression,
                job.next_run_secs,
                job.last_status orelse "pending",
                flags,
                job.command,
            });
        return .{ .success = true, .output = msg };
    }

    if (std.mem.eql(u8, action, "create") or std.mem.eql(u8, action, "add") or std.mem.eql(u8, action, "once")) {
        const command = stringArg(args, "command");
        const prompt = stringArg(args, "prompt");
        const model = stringArg(args, "model");
        if (command == null and prompt == null) return ToolResult.fail("Missing 'command' or 'prompt' parameter");
        if (command != null and prompt != null) return ToolResult.fail("Provide either 'command' or 'prompt', not both");
        if (prompt == null and session_target != .isolated) {
            return ToolResult.fail("session_target is only supported for agent jobs created with 'prompt'");
        }

        const one_shot = std.mem.eql(u8, action, "once");
        const schedule = if (one_shot)
            stringArg(args, "delay") orelse return ToolResult.fail("Missing 'delay' parameter for one-shot task")
        else
            stringArg(args, "expression") orelse return ToolResult.fail("Missing 'expression' parameter for cron job");

        const job = if (prompt) |job_prompt|
            if (one_shot)
                scheduler.addAgentOnce(schedule, job_prompt, model, delivery, repeat_delay_secs) catch |err|
                    return mutationFailure(allocator, "create one-shot agent task", err)
            else
                scheduler.addAgentJob(schedule, job_prompt, model, delivery) catch |err|
                    return mutationFailure(allocator, "create agent job", err)
        else if (one_shot)
            scheduler.addShellOnce(schedule, command.?, delivery) catch |err|
                return mutationFailure(allocator, "create one-shot task", err)
        else
            scheduler.addShellJob(schedule, command.?, delivery) catch |err|
                return mutationFailure(allocator, "create job", err);

        if (prompt != null) job.session_target = session_target;
        cron.saveJobs(scheduler) catch |err| {
            _ = scheduler.removeJob(job.id);
            return mutationFailure(allocator, "save scheduler state", err);
        };

        const msg = if (prompt) |job_prompt|
            if (one_shot and job.isWatcher())
                try std.fmt.allocPrint(allocator, "Created watcher {s} | runs at {d} | repeat_delay_secs={d} | prompt: {s}", .{ job.id, job.next_run_secs, job.repeat_delay_secs.?, job_prompt })
            else if (one_shot)
                try std.fmt.allocPrint(allocator, "Created one-shot agent task {s} | runs at {d} | prompt: {s}", .{ job.id, job.next_run_secs, job_prompt })
            else
                try std.fmt.allocPrint(allocator, "Created agent job {s} | {s} | prompt: {s}", .{ job.id, job.expression, job_prompt })
        else if (one_shot)
            try std.fmt.allocPrint(allocator, "Created one-shot task {s} | runs at {d} | cmd: {s}", .{ job.id, job.next_run_secs, job.command })
        else
            try std.fmt.allocPrint(allocator, "Created job {s} | {s} | cmd: {s}", .{ job.id, job.expression, job.command });
        return .{ .success = true, .output = msg };
    }

    if (std.mem.eql(u8, action, "update")) {
        const id = stringArg(args, "id") orelse return ToolResult.fail("Missing 'id' parameter for update action");
        const expression = stringArg(args, "expression");
        const command = stringArg(args, "command");
        const prompt = stringArg(args, "prompt");
        const model = stringArg(args, "model");
        const enabled = root.getBool(args, "enabled");
        const target = if (stringArg(args, "session_target")) |value|
            cron.SessionTarget.parseStrict(value) catch
                return ToolResult.fail("Invalid 'session_target' parameter: expected 'isolated' or 'main'")
        else
            null;
        if (expression == null and command == null and prompt == null and model == null and enabled == null and target == null and repeat_delay_secs == null) {
            return ToolResult.fail("Nothing to update");
        }
        if (!scheduler.updateJob(allocator, id, .{
            .expression = expression,
            .command = command,
            .prompt = prompt,
            .model = model,
            .enabled = enabled,
            .session_target = target,
            .repeat_delay_secs = repeat_delay_secs,
        })) {
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found or update invalid", .{id});
            return .{ .success = false, .output = "", .error_msg = msg };
        }
        cron.saveJobs(scheduler) catch |err| {
            cron.reloadJobs(scheduler) catch {};
            return mutationFailure(allocator, "save scheduler state", err);
        };
        const msg = try std.fmt.allocPrint(allocator, "Updated job {s}", .{id});
        return .{ .success = true, .output = msg };
    }

    if (std.mem.eql(u8, action, "cancel") or std.mem.eql(u8, action, "remove")) {
        const id = stringArg(args, "id") orelse return ToolResult.fail("Missing 'id' parameter for cancel action");
        if (!scheduler.removeJob(id)) {
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
            return .{ .success = false, .output = "", .error_msg = msg };
        }
        cron.saveJobs(scheduler) catch |err| {
            cron.reloadJobs(scheduler) catch {};
            return mutationFailure(allocator, "save scheduler state", err);
        };
        const msg = try std.fmt.allocPrint(allocator, "Cancelled job {s}", .{id});
        return .{ .success = true, .output = msg };
    }

    if (std.mem.eql(u8, action, "pause") or std.mem.eql(u8, action, "resume")) {
        const id = stringArg(args, "id") orelse return ToolResult.fail("Missing 'id' parameter");
        const is_pause = std.mem.eql(u8, action, "pause");
        const found = if (is_pause) scheduler.pauseJob(id) else scheduler.resumeJob(id);
        if (!found) {
            const msg = try std.fmt.allocPrint(allocator, "Job '{s}' not found", .{id});
            return .{ .success = false, .output = "", .error_msg = msg };
        }
        cron.saveJobs(scheduler) catch |err| {
            _ = if (is_pause) scheduler.resumeJob(id) else scheduler.pauseJob(id);
            return mutationFailure(allocator, "save scheduler state", err);
        };
        const verb: []const u8 = if (is_pause) "Paused" else "Resumed";
        const msg = try std.fmt.allocPrint(allocator, "{s} job {s}", .{ verb, id });
        return .{ .success = true, .output = msg };
    }

    const msg = try std.fmt.allocPrint(allocator, "Unknown action '{s}'", .{action});
    return .{ .success = false, .output = "", .error_msg = msg };
}

// ── Tests ───────────────────────────────────────────────────────────

test "schedule tool name" {
    var st = ScheduleTool{};
    const t = st.tool();
    try std.testing.expectEqualStrings("schedule", t.name());
}

test "schedule schema has action" {
    var st = ScheduleTool{};
    const t = st.tool();
    const schema = t.parametersJson();
    try std.testing.expect(std.mem.indexOf(u8, schema, "action") != null);
    try std.testing.expect(std.mem.indexOf(u8, schema, "repeat_delay") != null);
}

test "schedule disabled capability blocks calls and TLS cleanup restores access" {
    clearSchedulerCapabilities();
    defer clearSchedulerCapabilities();
    var st = ScheduleTool{};
    const args = try root.parseTestArgs("{\"action\":\"list\"}");
    defer args.deinit();

    setSchedulerCapabilities(true, true, 64, .{});
    const blocked = try st.execute(std.testing.allocator, args.value.object);
    try std.testing.expect(!blocked.success);
    try std.testing.expectEqualStrings("The schedule tool is disabled for this agent run", blocked.error_msg.?);

    clearSchedulerCapabilities();
    const allowed = try st.execute(std.testing.allocator, args.value.object);
    defer if (allowed.output.len > 0) std.testing.allocator.free(allowed.output);
    try std.testing.expect(allowed.success);
}

test "schedule list returns success" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"list\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    // Either "No scheduled jobs." or a formatted job list
    try std.testing.expect(result.output.len > 0);
}

test "schedule unknown action" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"explode\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "Unknown action") != null);
}

test "schedule create with expression" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"*/5 * * * *\", \"command\": \"echo hello\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    // Succeeds if HOME/.nullclaw is writable, otherwise may fail gracefully
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created job") != null);
    }
}

test "schedule create supports agent jobs with session_target" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"*/5 * * * *\", \"prompt\": \"Summarize release status\", \"model\": \"glm-cn/glm-5-turbo\", \"session_target\": \"main\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created agent job") != null);
    }
}

test "schedule create rejects cross-channel override without explicit chat_id" {
    var st = ScheduleTool{};
    st.setContext("telegram", "main", "chat-123", .direct, "chat-123", null);
    defer st.setContext(null, null, null, null, null, null);

    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"*/5 * * * *\", \"command\": \"echo hello\", \"channel\": \"signal\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);

    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "chat_id") != null);
}

test "schedule create rejects invalid session_target" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"*/5 * * * *\", \"prompt\": \"Summarize\", \"session_target\": \"primary\"}");
    defer parsed.deinit();

    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "session_target") != null);
}

// ── Additional schedule tests ───────────────────────────────────

test "schedule missing action" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "action") != null);
}

test "schedule get missing id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"get\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "id") != null);
}

test "schedule get nonexistent job" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"get\", \"id\": \"nonexistent-123\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
}

test "schedule cancel requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"cancel\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "schedule cancel nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"cancel\", \"id\": \"job-nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    // Job doesn't exist in the real scheduler, so cancel returns not-found or success if previously created
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule remove nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"remove\", \"id\": \"job-nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule pause nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"pause\", \"id\": \"job-nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule resume nonexistent job returns not found" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"resume\", \"id\": \"job-nonexistent\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    defer if (result.error_msg) |e| std.testing.allocator.free(e);
    if (!result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "not found") != null);
    }
}

test "schedule once creates one-shot task" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"once\", \"delay\": \"30m\", \"command\": \"echo later\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "one-shot") != null);
    }
}

test "schedule add creates recurring job" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"add\", \"expression\": \"0 * * * *\", \"command\": \"echo hourly\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    if (result.success) {
        try std.testing.expect(std.mem.indexOf(u8, result.output, "Created job") != null);
    }
}

test "schedule create missing command" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"* * * * *\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "command") != null or
        std.mem.indexOf(u8, result.error_msg.?, "prompt") != null);
}

test "schedule create missing expression" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"command\": \"echo hi\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "expression") != null);
}

test "schedule once missing delay" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"once\", \"command\": \"echo hi\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "delay") != null);
}

test "schedule rejects session_target for shell jobs" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"create\", \"expression\": \"* * * * *\", \"command\": \"echo hi\", \"session_target\": \"main\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "session_target") != null);
}

test "schedule pause requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"pause\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "schedule resume requires id" {
    var st = ScheduleTool{};
    const t = st.tool();
    const parsed = try root.parseTestArgs("{\"action\": \"resume\"}");
    defer parsed.deinit();
    const result = try t.execute(std.testing.allocator, parsed.value.object);
    try std.testing.expect(!result.success);
}

test "schedule uses live scheduler and persists created job" {
    var store_guard = try cron.TestCronStoreGuard.init(std.testing.allocator);
    defer store_guard.deinit();

    var scheduler = CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    cron.registerLiveScheduler(&scheduler);
    defer cron.clearLiveScheduler(&scheduler);

    var st = ScheduleTool{};
    const create_args = try root.parseTestArgs(
        "{\"action\":\"create\",\"expression\":\"*/17 * * * *\",\"command\":\"echo live\"}",
    );
    defer create_args.deinit();
    const created = try st.execute(std.testing.allocator, create_args.value.object);
    defer if (created.output.len > 0) std.testing.allocator.free(created.output);
    try std.testing.expect(created.success);
    try std.testing.expectEqual(@as(usize, 1), scheduler.listJobs().len);
    const id = scheduler.listJobs()[0].id;
    try std.testing.expect(std.mem.indexOf(u8, created.output, id) != null);

    const get_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"action\":\"get\",\"id\":\"{s}\"}}", .{id});
    defer std.testing.allocator.free(get_json);
    const get_args = try root.parseTestArgs(get_json);
    defer get_args.deinit();
    const got = try st.execute(std.testing.allocator, get_args.value.object);
    defer if (got.output.len > 0) std.testing.allocator.free(got.output);
    try std.testing.expect(got.success);
    try std.testing.expect(std.mem.indexOf(u8, got.output, id) != null);

    const list_args = try root.parseTestArgs("{\"action\":\"list\"}");
    defer list_args.deinit();
    const listed = try st.execute(std.testing.allocator, list_args.value.object);
    defer if (listed.output.len > 0) std.testing.allocator.free(listed.output);
    try std.testing.expect(listed.success);
    try std.testing.expect(std.mem.indexOf(u8, listed.output, id) != null);

    var reloaded = CronScheduler.init(std.testing.allocator, 8, true);
    defer reloaded.deinit();
    try cron.loadJobsStrict(&reloaded);
    try std.testing.expect(reloaded.getJob(id) != null);
}

test "schedule Terra blank fields inherit Discord delivery routing" {
    var store_guard = try cron.TestCronStoreGuard.init(std.testing.allocator);
    defer store_guard.deinit();

    var scheduler = CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    cron.registerLiveScheduler(&scheduler);
    defer cron.clearLiveScheduler(&scheduler);

    var st = ScheduleTool{};
    st.setContext("discord", "discord-main", "channel-42", .direct, "user-42", null);
    defer st.setContext(null, null, null, null, null, null);

    // Regression: Terra emits every optional string field as an empty string.
    const args = try root.parseTestArgs(
        "{\"action\":\"create\",\"expression\":\"*/19 * * * *\",\"delay\":\"\",\"repeat_delay\":\"\",\"prompt\":\"\",\"command\":\"echo terra\",\"model\":\"\",\"session_target\":\"\",\"channel\":\"\",\"account_id\":\"\",\"chat_id\":\"\"}",
    );
    defer args.deinit();
    const result = try st.execute(std.testing.allocator, args.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);

    const job = scheduler.listJobs()[0];
    try std.testing.expectEqual(cron.JobType.shell, job.job_type);
    try std.testing.expect(job.model == null);
    try std.testing.expectEqualStrings("discord", job.delivery.channel.?);
    try std.testing.expectEqualStrings("discord-main", job.delivery.account_id.?);
    try std.testing.expectEqualStrings("channel-42", job.delivery.to.?);
    try std.testing.expectEqualStrings("user-42", job.delivery.peer_id.?);
}

test "schedule treats required blank strings as missing" {
    var st = ScheduleTool{};
    const payloads = [_][]const u8{
        "{\"action\":\"   \"}",
        "{\"action\":\"create\",\"expression\":\" \\t\",\"command\":\"echo hi\"}",
        "{\"action\":\"once\",\"delay\":\"\\n\",\"command\":\"echo hi\"}",
        "{\"action\":\"get\",\"id\":\" \\r\"}",
    };
    for (payloads) |payload| {
        const args = try root.parseTestArgs(payload);
        defer args.deinit();
        const result = try st.execute(std.testing.allocator, args.value.object);
        try std.testing.expect(!result.success);
    }
}

test "schedule validates repeat_delay watcher shape and duration" {
    var st = ScheduleTool{};
    const payloads = [_][]const u8{
        "{\"action\":\"create\",\"expression\":\"* * * * *\",\"prompt\":\"check\",\"repeat_delay\":\"5m\"}",
        "{\"action\":\"once\",\"delay\":\"1m\",\"command\":\"echo check\",\"repeat_delay\":\"5m\"}",
        "{\"action\":\"once\",\"delay\":\"1m\",\"prompt\":\"check\",\"repeat_delay\":\"0s\"}",
        "{\"action\":\"once\",\"delay\":\"1m\",\"prompt\":\"check\",\"repeat_delay\":5}",
    };
    for (payloads) |payload| {
        const args = try root.parseTestArgs(payload);
        defer args.deinit();
        const result = try st.execute(std.testing.allocator, args.value.object);
        try std.testing.expect(!result.success);
        try std.testing.expect(std.mem.indexOf(u8, result.error_msg.?, "repeat_delay") != null);
    }
}

test "schedule creates durable watcher and exposes repeat state" {
    var store_guard = try cron.TestCronStoreGuard.init(std.testing.allocator);
    defer store_guard.deinit();

    var scheduler = CronScheduler.init(std.testing.allocator, 64, true);
    defer scheduler.deinit();
    cron.registerLiveScheduler(&scheduler);
    defer cron.clearLiveScheduler(&scheduler);

    var st = ScheduleTool{};
    const args = try root.parseTestArgs(
        "{\"action\":\"once\",\"delay\":\"1m\",\"repeat_delay\":\"5m\",\"prompt\":\"Check import\",\"session_target\":\"main\"}",
    );
    defer args.deinit();
    const result = try st.execute(std.testing.allocator, args.value.object);
    defer if (result.output.len > 0) std.testing.allocator.free(result.output);
    try std.testing.expect(result.success);
    try std.testing.expect(std.mem.indexOf(u8, result.output, "Created watcher") != null);

    const job = scheduler.listJobs()[0];
    try std.testing.expect(job.isWatcher());
    try std.testing.expectEqual(@as(?i64, 300), job.repeat_delay_secs);
    try std.testing.expectEqual(cron.SessionTarget.main, job.session_target);

    const get_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"action\":\"get\",\"id\":\"{s}\"}}", .{job.id});
    defer std.testing.allocator.free(get_json);
    const get_args = try root.parseTestArgs(get_json);
    defer get_args.deinit();
    const got = try st.execute(std.testing.allocator, get_args.value.object);
    defer if (got.output.len > 0) std.testing.allocator.free(got.output);
    try std.testing.expect(got.success);
    try std.testing.expect(std.mem.indexOf(u8, got.output, "[watcher]") != null);
    try std.testing.expect(std.mem.indexOf(u8, got.output, "repeat_delay_secs=300") != null);
}

test "schedule watcher CRUD ignores Terra blank optional fields" {
    var store_guard = try cron.TestCronStoreGuard.init(std.testing.allocator);
    defer store_guard.deinit();

    var scheduler = CronScheduler.init(std.testing.allocator, 8, true);
    defer scheduler.deinit();
    cron.registerLiveScheduler(&scheduler);
    defer cron.clearLiveScheduler(&scheduler);

    var st = ScheduleTool{};
    const create_args = try root.parseTestArgs(
        "{\"action\":\"once\",\"delay\":\"1m\",\"repeat_delay\":\"5m\",\"prompt\":\"check one\",\"command\":\"\",\"model\":\"\",\"id\":\"\",\"channel\":\"\",\"account_id\":\"\",\"chat_id\":\"\",\"session_target\":\"isolated\"}",
    );
    defer create_args.deinit();
    const created = try st.execute(std.testing.allocator, create_args.value.object);
    defer if (created.output.len > 0) std.testing.allocator.free(created.output);
    try std.testing.expect(created.success);
    const id = scheduler.listJobs()[0].id;

    const pause_json = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"action\":\"pause\",\"expression\":\"\",\"delay\":\"\",\"repeat_delay\":\"\",\"command\":\"\",\"prompt\":\"\",\"model\":\"\",\"id\":\"{s}\",\"channel\":\"\",\"account_id\":\"\",\"chat_id\":\"\",\"session_target\":\"isolated\"}}",
        .{id},
    );
    defer std.testing.allocator.free(pause_json);
    const pause_args = try root.parseTestArgs(pause_json);
    defer pause_args.deinit();
    const paused = try st.execute(std.testing.allocator, pause_args.value.object);
    defer if (paused.output.len > 0) std.testing.allocator.free(paused.output);
    try std.testing.expect(paused.success);
    try std.testing.expect(scheduler.getJob(id).?.paused);

    const update_json = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"action\":\"update\",\"id\":\"{s}\",\"expression\":\"\",\"delay\":\"\",\"repeat_delay\":\"10m\",\"command\":\"\",\"prompt\":\"check two\",\"model\":\"\",\"channel\":\"\",\"account_id\":\"\",\"chat_id\":\"\",\"session_target\":\"isolated\"}}",
        .{id},
    );
    defer std.testing.allocator.free(update_json);
    const update_args = try root.parseTestArgs(update_json);
    defer update_args.deinit();
    const updated = try st.execute(std.testing.allocator, update_args.value.object);
    defer if (updated.output.len > 0) std.testing.allocator.free(updated.output);
    try std.testing.expect(updated.success);
    try std.testing.expectEqualStrings("check two", scheduler.getJob(id).?.prompt.?);
    try std.testing.expectEqual(@as(?i64, 600), scheduler.getJob(id).?.repeat_delay_secs);

    const resume_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"action\":\"resume\",\"repeat_delay\":\"\",\"id\":\"{s}\"}}", .{id});
    defer std.testing.allocator.free(resume_json);
    const resume_args = try root.parseTestArgs(resume_json);
    defer resume_args.deinit();
    const resumed = try st.execute(std.testing.allocator, resume_args.value.object);
    defer if (resumed.output.len > 0) std.testing.allocator.free(resumed.output);
    try std.testing.expect(resumed.success);
    try std.testing.expect(!scheduler.getJob(id).?.paused);

    const remove_json = try std.fmt.allocPrint(std.testing.allocator, "{{\"action\":\"remove\",\"repeat_delay\":\"\",\"id\":\"{s}\"}}", .{id});
    defer std.testing.allocator.free(remove_json);
    const remove_args = try root.parseTestArgs(remove_json);
    defer remove_args.deinit();
    const removed = try st.execute(std.testing.allocator, remove_args.value.object);
    defer if (removed.output.len > 0) std.testing.allocator.free(removed.output);
    try std.testing.expect(removed.success);
    try std.testing.expectEqual(@as(usize, 0), scheduler.listJobs().len);
}
