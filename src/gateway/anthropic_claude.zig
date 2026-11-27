const std = @import("std");
const claude_oauth = @import("../core/auth/claude_oauth.zig");
const claude_session = @import("../core/auth/claude_session.zig");
const secret = @import("../core/auth/secret.zig");
const streams = @import("../core/agent/stream_provider.zig");
const io_mod = @import("../core/shared/io.zig");
const image_attachments = @import("../core/images/image_attachments.zig");
const model_provider = @import("../core/config/model_provider.zig");
const client = @import("client.zig");
const configured_transport = @import("configured_transport.zig");
const messages = @import("anthropic_messages_protocol.zig");
const chat_codec = @import("chat_completions_protocol.zig");
const protocol = @import("claude_code_protocol.zig");

const Allocator = std.mem.Allocator;
const endpoint = "https://api.anthropic.com/v1/messages?beta=true";
const e2e_endpoint_env = "FX_TEST_CLAUDE_MESSAGES_URL";
const max_error_body_bytes = 64 * 1024;
const provider_id: model_provider.ProviderId = .claude;

pub const agent_stream_provider = streams.Provider{
    .stream_fn = streamCompletion,
    .build_request_fn = buildForProvider,
    .project_replay_fn = messages.project_replay,
};

fn buildForProvider(_: ?*anyopaque, alloc: Allocator, request: streams.RequestData) ![]u8 {
    return buildRequest(alloc, request);
}

fn wireRequest(input: streams.RequestData) streams.RequestData {
    var request = input;
    // These models decline forced tool calls. Leave the tools available.
    if (request.tool_choice == .required and
        (std.mem.startsWith(u8, request.model, "claude-fable-") or std.mem.startsWith(u8, request.model, "claude-mythos-")))
    {
        request.tool_choice = .auto;
    }
    // The subscription wire uses the model's defaults, not gateway options.
    request.provider_options = .{};
    return request;
}

/// Returns the owned wire body, including the SDK system blocks, so capacity
/// measurement and streaming use exactly the same bytes.
pub fn buildRequest(alloc: Allocator, input: streams.RequestData) ![]u8 {
    const budget: image_attachments.CaptureBudget = if (input.budget) |b|
        .{ .deadline = b.deadline, .cancel_flag = b.cancel_flag }
    else
        .{};
    try budget.check();
    var request = wireRequest(input);
    request.max_output_tokens = input.max_output_tokens orelse 8192;
    const json = try messages.build_request(alloc, request, .{ .tool_choice_mode = .send, .provider = &provider_id });
    defer alloc.free(json);
    try budget.check();
    const prepared = try protocol.prepare(alloc, json);
    errdefer alloc.free(prepared);
    try budget.check();
    return prepared;
}

fn streamCompletion(_: ?*anyopaque, alloc: Allocator, request: streams.ModelRequest) !streams.Result {
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
    _ = try authOf(request.credential);
    const payload = request.prepared_request_body orelse try buildRequest(alloc, request.data());
    defer if (request.prepared_request_body == null) alloc.free(payload);
    return streamPrepared(alloc, request, payload);
}

const Auth = struct { token: []const u8, account_id: []const u8 };

fn authOf(credential: streams.CredentialLease) !Auth {
    if (credential.credentialSource() != .claude_subscription) return error.ClaudeSubscriptionCredentialRequired;
    const token = credential.secret() orelse return error.ClaudeSubscriptionCredentialRequired;
    if (!validToken(token)) return error.InvalidClaudeSubscriptionCredential;
    const account_id = credential.accountId() orelse return error.ClaudeSubscriptionAccountRequired;
    if (!claude_session.validAccountId(account_id)) return error.InvalidClaudeSubscriptionAccount;
    return .{ .token = token, .account_id = account_id };
}

pub fn validToken(token: []const u8) bool {
    if (token.len == 0 or token.len > 16 * 1024) return false;
    for (token) |byte| if (byte <= 0x20 or byte >= 0x7f) return false;
    return true;
}

fn messagesEndpoint() ![]const u8 {
    const override = io_mod.getenv(e2e_endpoint_env) orelse return endpoint;
    if (!client.isLoopbackHttpUrl(override)) return error.InvalidE2EAnthropicClaudeEndpoint;
    return override;
}

fn expired(deadline: ?std.Io.Clock.Timestamp) bool {
    const limit = deadline orelse return false;
    return !std.Io.Clock.Timestamp.compare(std.Io.Clock.Timestamp.now(io_mod.getIo(), .awake), .lt, limit);
}

fn phaseDeadline(milliseconds: i64, caller: ?std.Io.Clock.Timestamp) std.Io.Clock.Timestamp {
    const phase = std.Io.Clock.Timestamp.fromNow(io_mod.getIo(), .{ .clock = .awake, .raw = .fromMilliseconds(milliseconds) });
    if (caller) |deadline| if (std.Io.Clock.Timestamp.compare(deadline, .lt, phase)) return deadline;
    return phase;
}

pub fn streamPrepared(alloc: Allocator, request: streams.ModelRequest, payload: []const u8) !streams.Result {
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
    if (expired(request.deadline)) return error.Timeout;
    const auth = try authOf(request.credential);
    const target = try messagesEndpoint();
    var result = post(alloc, request, payload, auth, target) catch |err| {
        if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
        if (expired(request.deadline)) return error.Timeout;
        request.attempt_evidence.network_failure = client.networkFailureEvidence(err, request.delivery.load());
        return err;
    };
    if (request.cancel_flag.load(.seq_cst) or expired(request.deadline)) {
        result.deinit(alloc);
        return if (request.cancel_flag.load(.seq_cst)) error.Cancelled else error.Timeout;
    }
    return result;
}

const OpenResult = struct {
    opened: client.OpenedRequest,

    pub fn deinit(self: *OpenResult, _: Allocator) void {
        self.opened.deinit();
    }
};

const Open = struct {
    uri: std.Uri,
    options: std.http.Client.RequestOptions,

    pub fn run(self: Open) !OpenResult {
        return .{ .opened = try client.openRequestOnJob(.POST, self.uri, self.options) };
    }
};

fn post(alloc: Allocator, request: streams.ModelRequest, payload: []const u8, auth: Auth, target: []const u8) !streams.Result {
    const uri = try std.Uri.parse(target);
    const authorization = try alloc.print("Bearer {s}", .{auth.token});
    defer secret.zeroAndFree(alloc, authorization);
    var seed: [16]u8 = undefined;
    io_mod.getIo().random(&seed);
    const request_id = protocol.uuid(seed);
    var session_id: [36]u8 = undefined;
    var headers = [_]std.http.Header{
        .{ .name = "anthropic-version", .value = claude_oauth.anthropic_api_version },
        .{ .name = "anthropic-beta", .value = claude_oauth.messages_beta },
        .{ .name = "anthropic-account-uuid", .value = auth.account_id },
        .{ .name = "originator", .value = claude_oauth.messages_originator },
        .{ .name = "accept", .value = "application/json" },
        .{ .name = "x-client-request-id", .value = &request_id },
        .{ .name = "x-app", .value = "cli" },
        .{ .name = "anthropic-dangerous-direct-browser-access", .value = "true" },
        undefined,
    };
    var header_count = headers.len - 1;
    if (request.session_id) |id| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(id, &digest, .{});
        session_id = protocol.uuid(digest[0..16].*);
        headers[header_count] = .{ .name = "x-claude-code-session-id", .value = &session_id };
        header_count += 1;
    }
    const connect_deadline = phaseDeadline(configured_transport.default_connect_ms, request.deadline);
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
    if (expired(connect_deadline)) return error.Timeout;
    try request.admission.admit();
    var opened = try client.runBoundedHttpOperation(OpenResult, alloc, request.cancel_flag, connect_deadline, Open{
        .uri = uri,
        .options = .{
            .headers = .{
                .authorization = .{ .override = authorization },
                .user_agent = .{ .override = protocol.user_agent },
                .content_type = .{ .override = "application/json" },
                .accept_encoding = .omit,
            },
            .extra_headers = headers[0..header_count],
            .keep_alive = false,
            .redirect_behavior = .unhandled,
        },
    });
    defer opened.deinit(alloc);
    const http = &opened.opened.request;
    // Messages ends at message_stop, not at EOF. Do not drain unread bytes
    // during Zig's request deinit, including on a parser error.
    defer if (http.connection) |connection| {
        connection.closing = true;
    };
    var watch: client.ConnectionWatch = .init(.{
        .timeout_ms = configured_transport.default_first_response_ms,
        .stall_timeout_ms = client.ConnectionWatch.bodyStallTimeoutMs(request.deadline),
    });
    defer watch.stop();
    if (http.connection) |connection| try watch.start(request.cancel_flag, request.deadline, connection.stream_writer.stream);
    if (watch.armHead()) |err| return err;
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;
    http.transfer_encoding = .{ .content_length = payload.len };
    var send_buffer: [8192]u8 = undefined;
    request.delivery.markPossiblySent();
    var body = http.sendBodyUnflushed(&send_buffer) catch |err| return watch.failure(err);
    body.writer.writeAll(payload) catch |err| return watch.failure(err);
    body.end() catch |err| return watch.failure(err);
    if (http.connection) |connection| connection.flush() catch |err| return watch.failure(err);

    var response = http.receiveHead(&.{}) catch |err| return watch.failure(err);
    if (watch.commitHead()) |err| return err;
    const status = response.head.status;
    const retry_after = client.retryAfterSeconds(response.head);
    var transfer: [64 * 1024]u8 = undefined;
    const reader = response.reader(&transfer);
    var result = if (status == .ok) result: {
        var limits: messages.Limits = .{};
        if (request.content_capture_limit) |cap| limits.content_bytes = @min(limits.content_bytes, cap);
        break :result messages.consume_stream(alloc, reader, wireRequest(request.data()), limits, request.events, request.cancel_flag, watch.progress()) catch |err| return watch.failure(err);
    } else result: {
        watch.stop();
        watch = .init(.{ .patient = true });
        const error_deadline = phaseDeadline(30_000, request.deadline);
        if (http.connection) |connection| try watch.start(request.cancel_flag, error_deadline, connection.stream_writer.stream);
        const detail = reader.allocRemaining(alloc, .limited(max_error_body_bytes)) catch |err| switch (err) {
            error.StreamTooLong => try alloc.dupe(u8, "Anthropic Claude error response exceeded the local limit"),
            else => return if (expired(error_deadline)) error.Timeout else watch.failure(err),
        };
        break :result streams.Result{ .failed = .{
            .kind = client.httpFailureKind(alloc, .fromHttpStatus(status), detail),
            .http_status = status,
            .detail = detail,
            .retry_after_seconds = retry_after,
            .ownership = .owned,
        } };
    };
    errdefer result.deinit(alloc);
    if (watch.finish()) |err| return err;
    if (result == .failed and result.failed.ownership == .owned) {
        if (result.failed.detail) |detail| {
            result.failed.detail = null;
            result.failed.detail = try chat_codec.redactOwnedErrorBody(alloc, @constCast(detail), auth.token);
        }
    }
    return result;
}

test "Claude builds the exact prepared Messages body" {
    const alloc = std.testing.allocator;
    const body = try agent_stream_provider.buildRequest(alloc, .{
        .model = "claude-sonnet-4-6",
        .instructions = &.{.{ .role = .system, .content = "Use fx permissions." }},
        .messages = &.{.{ .role = .user, .content = "Hello." }},
        .tool_choice = .none,
        .provider_options = .{},
    });
    defer alloc.free(body.?);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, body.?, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 8192), obj.get("max_tokens").?.integer);
    try std.testing.expect(obj.get("stream").?.bool);
    const system = obj.get("system").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), system.len);
    try std.testing.expectEqualStrings("Use fx permissions.", system[2].object.get("text").?.string);
}

fn denyAdmission(raw: *anyopaque) !void {
    const count: *usize = @ptrCast(@alignCast(raw));
    count.* += 1;
    return error.TestClaudeAdmissionDenied;
}

fn ignoreEvent(_: *anyopaque, _: streams.Event) void {}

test "Claude checks admission exactly once before opening or marking delivery" {
    const env = try @import("raw_answer_testing.zig").Env.install(std.testing.allocator, &.{.{ e2e_endpoint_env, "http://127.0.0.1:1/v1/messages" }});
    defer env.deinit();
    var calls: usize = 0;
    var cancel: std.atomic.Value(bool) = .init(false);
    var delivery = streams.DeliveryCertainty.init();
    var evidence: streams.AttemptEvidence = .{};
    const request: streams.ModelRequest = .{
        .credential = .{ .direct = .{ .source = .claude_subscription, .secret_bytes = "fixture-token", .account_id = "aabbccdd-1234-4567-8901-aabbccddeeff" } },
        .model = "claude-sonnet-4-6",
        .retry_count = 1,
        .messages = &.{.{ .role = .user, .content = "Hello." }},
        .tool_choice = .none,
        .provider_options = .{},
        .trace_ctx = .{},
        .content_capture_limit = null,
        .delivery = &delivery,
        .attempt_evidence = &evidence,
        .events = .{ .context = &calls, .emit_fn = ignoreEvent },
        .admission = .{ .context = &calls, .admit_fn = denyAdmission },
        .cancel_flag = &cancel,
    };
    try std.testing.expectError(error.TestClaudeAdmissionDenied, agent_stream_provider.stream(std.testing.allocator, request));
    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expectEqual(streams.DeliveryCertainty.State.definitely_unsent, delivery.load());
}

const TestMessagesServer = struct {
    server: *std.Io.net.Server,
    payload: []const u8,
    stopping: std.atomic.Value(bool) = .init(false),
    sent: std.Io.Event = .unset,
    finish: std.Io.Event = .unset,
    failure: ?anyerror = null,

    fn run(self: *TestMessagesServer) void {
        self.serve() catch |err| {
            self.failure = err;
        };
    }

    fn serve(self: *TestMessagesServer) !void {
        const io = std.testing.io;
        const listener = @import("../core/shared/testing_listener.zig");
        const socket = (try listener.acceptUnlessStopping(self.server, io, &self.stopping)) orelse return;
        defer socket.close(io);
        var read_buffer: [4096]u8 = undefined;
        var write_buffer: [4096]u8 = undefined;
        var reader = socket.reader(io, &read_buffer);
        var writer = socket.writer(io, &write_buffer);
        var server = std.http.Server.init(&reader.interface, &writer.interface);
        var request = try server.receiveHead();
        try std.testing.expectEqual(.POST, request.head.method);
        try std.testing.expectEqualStrings("/v1/messages?beta=true", request.head.target);
        var headers = request.iterateHeaders();
        var authorization: ?[]const u8 = null;
        var user_agent: ?[]const u8 = null;
        var account_id: ?[]const u8 = null;
        while (headers.next()) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, "authorization")) authorization = header.value;
            if (std.ascii.eqlIgnoreCase(header.name, "user-agent")) user_agent = header.value;
            if (std.ascii.eqlIgnoreCase(header.name, "anthropic-account-uuid")) account_id = header.value;
        }
        try std.testing.expectEqualStrings("Bearer fixture-token", authorization orelse "");
        try std.testing.expectEqualStrings(protocol.user_agent, user_agent orelse "");
        try std.testing.expectEqualStrings("acct_claude_fixture", account_id orelse "");
        var transfer: [1024]u8 = undefined;
        const payload = try request.readerExpectNone(&transfer).allocRemaining(std.testing.allocator, .limited(8192));
        defer std.testing.allocator.free(payload);
        try std.testing.expectEqualStrings(self.payload, payload);

        // Never send the last chunk; only message_stop should end the reply.
        const events =
            "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fixture\",\"content\":[],\"usage\":{\"input_tokens\":4,\"output_tokens\":0}}}\n\n" ++
            "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" ++
            "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello from Claude.\"}}\n\n" ++
            "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n" ++
            "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":5}}\n\n" ++
            "data: {\"type\":\"message_stop\"}\n\n";
        try writer.interface.print("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n{x}\r\n{s}\r\n", .{ events.len, events });
        try writer.interface.flush();
        self.sent.set(io);
        self.finish.waitUncancelable(io);
    }
};

fn countAdmission(raw: *anyopaque) !void {
    const count: *usize = @ptrCast(@alignCast(raw));
    count.* += 1;
}

test "Claude native POST sends the exact prepared body and returns at message_stop" {
    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const address: std.Io.net.IpAddress = .{ .ip4 = .loopback(0) };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    const url = try alloc.print("http://127.0.0.1:{d}/v1/messages?beta=true", .{server.socket.address.getPort()});
    defer alloc.free(url);
    const env = try @import("raw_answer_testing.zig").Env.install(alloc, &.{.{ e2e_endpoint_env, url }});
    defer env.deinit();
    var calls: usize = 0;
    var cancel: std.atomic.Value(bool) = .init(false);
    var delivery = streams.DeliveryCertainty.init();
    var evidence: streams.AttemptEvidence = .{};
    var request: streams.ModelRequest = .{
        .credential = .{ .direct = .{ .source = .claude_subscription, .secret_bytes = "fixture-token", .account_id = "acct_claude_fixture" } },
        .model = "claude-sonnet-4-6",
        .retry_count = 1,
        .messages = &.{.{ .role = .user, .content = "Hello." }},
        .tool_choice = .none,
        .provider_options = .{},
        .trace_ctx = .{},
        .content_capture_limit = null,
        .delivery = &delivery,
        .attempt_evidence = &evidence,
        .events = .{ .context = &calls, .emit_fn = ignoreEvent },
        .admission = .{ .context = &calls, .admit_fn = countAdmission },
        .cancel_flag = &cancel,
    };
    const payload = try buildRequest(alloc, request.data());
    defer alloc.free(payload);
    request.prepared_request_body = payload;
    request.deadline = phaseDeadline(5_000, null);
    var fixture: TestMessagesServer = .{ .server = &server, .payload = payload };
    const thread = try std.Thread.spawn(.{}, TestMessagesServer.run, .{&fixture});
    const result = agent_stream_provider.stream(alloc, request);
    fixture.stopping.store(true, .seq_cst);
    fixture.finish.set(io);
    thread.join();
    var completion = try result;
    defer completion.deinit(alloc);
    if (fixture.failure) |err| return err;
    try std.testing.expect(fixture.sent.isSet());
    try std.testing.expectEqual(@as(usize, 1), calls);
    try std.testing.expectEqual(streams.DeliveryCertainty.State.possibly_sent, delivery.load());
    try std.testing.expect(completion == .completed);
    try std.testing.expectEqualStrings("Hello from Claude.", completion.completed.completion.content.?);
}
