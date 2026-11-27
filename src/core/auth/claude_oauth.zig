const std = @import("std");
const browser_callback = @import("browser_callback.zig");
const claude_session = @import("claude_session.zig");
const debug_trace = @import("../shared/debug_trace.zig");
const host = @import("../hosts/host.zig");
const host_target = @import("../hosts/target.zig");
const io_mod = @import("../shared/io.zig");
const login_flow = @import("login_flow.zig");
const oauth = @import("oauth.zig");
const oauth_transport = @import("oauth_transport.zig");
const secret = @import("secret.zig");

const Allocator = std.mem.Allocator;

const client_id = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
const issuer_url = "https://claude.ai";
const authorize_url = "https://claude.ai/oauth/authorize";
const token_url = "https://api.anthropic.com/v1/oauth/token";
const refresh_url = "https://platform.claude.com/v1/oauth/token";
const userinfo_url = "https://api.anthropic.com/api/oauth/profile";
pub const anthropic_api_version = "2023-06-01";
const oauth_beta = "oauth-2025-04-20";
pub const messages_beta = oauth_beta ++ ",claude-code-20250219";
pub const messages_originator = "claude-code";
pub const messages_user_agent = "claude-cli/2.1.326 (external, cli)";
const oauth_api_headers = [_]std.http.Header{
    .{ .name = "anthropic-version", .value = anthropic_api_version },
    .{ .name = "anthropic-beta", .value = oauth_beta },
};
const e2e_authorize_url_env = "FX_TEST_CLAUDE_AUTHORIZE_URL";
const e2e_token_url_env = "FX_TEST_CLAUDE_TOKEN_URL";
const e2e_userinfo_url_env = "FX_TEST_CLAUDE_USERINFO_URL";
const browser_scope = "user:profile user:inference user:sessions:claude_code user:mcp_servers";
const browser_callback_port: u16 = 54545;
const browser_callback_path = "/callback";
const browser_redirect_uri = "http://localhost:54545" ++ browser_callback_path;
const browser_login_timeout_seconds: i64 = 5 * 60;

pub const RefreshMode = union(enum) {
    if_needed,
    force,
    stored,
    /// Rotate only if the stored login still needs to replace the rejected token.
    replace_rejected: []const u8,
};

pub const Access = struct {
    access_token: []u8,
    account_id: []u8,
    refresh_after_ms: i64,

    pub fn deinit(self: *Access, alloc: Allocator) void {
        secret.zeroAndFree(alloc, self.access_token);
        alloc.free(self.account_id);
        self.* = undefined;
    }
};

const BrowserLoginContext = struct {
    listeners: BrowserListeners,
    redirect_uri: []u8,
    code_verifier: []u8,
    state: []u8,
    manual_code_mutex: std.Io.Mutex = .init,
    manual_code: ?[]u8 = null,
    pending_callback: ?browser_callback.Accepted(BrowserCallback) = null,

    fn deinit(self: *BrowserLoginContext, alloc: Allocator) void {
        self.finishCallback(alloc, false);
        self.listeners.deinit();
        alloc.free(self.redirect_uri);
        secret.zeroAndFree(alloc, self.code_verifier);
        secret.zeroAndFree(alloc, self.state);
        if (self.manual_code) |code| secret.zeroAndFree(alloc, code);
        self.* = undefined;
    }

    fn finishCallback(self: *BrowserLoginContext, alloc: Allocator, saved: bool) void {
        var callback = self.pending_callback orelse return;
        self.pending_callback = null;
        defer callback.deinit();
        defer callback.callback.deinit(alloc);
        callback.respond(if (saved) .ok else .failed) catch |err| {
            debug_trace.logf("auth", "Claude completion response failed err={s}", .{@errorName(err)});
        };
    }

    fn submitManualCode(self: *BrowserLoginContext, alloc: Allocator, input: []const u8) !void {
        const parsed = try parsePastedAuthorizationInput(alloc, input, self.state);

        self.manual_code_mutex.lockUncancelable(io_mod.getIo());
        defer self.manual_code_mutex.unlock(io_mod.getIo());
        if (self.manual_code) |pending| secret.zeroAndFree(alloc, pending);
        self.manual_code = parsed.code;
    }

    fn takeManualCode(self: *BrowserLoginContext) ?[]u8 {
        self.manual_code_mutex.lockUncancelable(io_mod.getIo());
        defer self.manual_code_mutex.unlock(io_mod.getIo());
        const code = self.manual_code;
        self.manual_code = null;
        return code;
    }
};

const PreparedBrowserLogin = struct {
    prepared: login_flow.PreparedLogin,
    context: *BrowserLoginContext,
};

pub fn startSignIn(
    runtime: *login_flow.SignInRuntime,
    alloc: Allocator,
    transport: oauth_transport.Provider,
) !bool {
    if (comptime host_target.is_wasm) return error.ClaudeOAuthUnavailable;
    try claude_session.requireSignInStorage();
    const browser = try prepareBrowserSignIn(alloc);
    return runtime.startPrepared(
        alloc,
        browser.prepared,
        .{
            .ctx = browser.context,
            .deinit_ctx = deinitBrowserLoginContext,
            .oauth_transport = transport,
            .poll = .{
                .ctx = browser.context,
                .poll_device_token = pollBrowserToken,
            },
            .complete = completeSignIn,
            .save = saveSignIn,
            .finish = finishSignIn,
            .submit_manual_code = submitBrowserManualCode,
        },
    );
}

fn submitBrowserManualCode(raw: ?*anyopaque, alloc: Allocator, code: []const u8) !void {
    const context: *BrowserLoginContext = @ptrCast(@alignCast(raw.?));
    try context.submitManualCode(alloc, code);
}

fn prepareBrowserSignIn(alloc: Allocator) !PreparedBrowserLogin {
    const configured_authorize = try configuredEndpoint(alloc, e2e_authorize_url_env, authorize_url);
    defer alloc.free(configured_authorize);
    const configured_token_endpoint = try configuredEndpoint(alloc, e2e_token_url_env, token_url);
    errdefer alloc.free(configured_token_endpoint);

    var listeners = bindBrowserCallback(browser_callback_port) catch |err| switch (err) {
        error.AddressInUse => try bindBrowserCallback(0),
        else => return err,
    };
    errdefer listeners.deinit();
    const callback_port = listeners.ipv4.socket.address.getPort();
    const redirect_uri = try alloc.print(
        "http://localhost:{d}" ++ browser_callback_path,
        .{callback_port},
    );
    errdefer alloc.free(redirect_uri);
    const code_verifier = try oauth.randomUrlSafeSecret(alloc);
    errdefer secret.zeroAndFree(alloc, code_verifier);
    const state = try oauth.randomUrlSafeSecret(alloc);
    errdefer secret.zeroAndFree(alloc, state);
    const code_challenge = try oauth.pkceChallengeAlloc(alloc, code_verifier);
    defer alloc.free(code_challenge);
    const authorization_url = try buildBrowserAuthorizationUrl(
        alloc,
        configured_authorize,
        redirect_uri,
        code_challenge,
        state,
    );
    errdefer alloc.free(authorization_url);

    const context = try alloc.create(BrowserLoginContext);
    errdefer alloc.destroy(context);
    const prepared = try login_flow.prepareBrowserLogin(alloc, .{
        .issuer = issuer_url,
        .authorization_endpoint_suffix = "/oauth/authorize",
        .token_endpoint = configured_token_endpoint,
        .verification_uri = authorization_url,
        .client_id = client_id,
        .expires_in = browser_login_timeout_seconds,
    });
    context.* = .{
        .listeners = listeners,
        .redirect_uri = redirect_uri,
        .code_verifier = code_verifier,
        .state = state,
    };

    return .{
        .prepared = prepared,
        .context = context,
    };
}

fn deinitBrowserLoginContext(raw: ?*anyopaque, alloc: Allocator) void {
    const context: *BrowserLoginContext = @ptrCast(@alignCast(raw.?));
    context.deinit(alloc);
    alloc.destroy(context);
}

const BrowserListeners = struct {
    ipv4: std.Io.net.Server,
    ipv6: ?std.Io.net.Server,

    fn deinit(self: *BrowserListeners) void {
        if (self.ipv6) |*listener| listener.deinit(io_mod.getIo());
        self.ipv4.deinit(io_mod.getIo());
    }
};

fn bindBrowserCallback(port: u16) !BrowserListeners {
    const ipv4: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var primary = try ipv4.listen(io_mod.getIo(), .{});
    errdefer primary.deinit(io_mod.getIo());
    const ipv6: std.Io.net.IpAddress = .{ .ip6 = .loopback(primary.socket.address.getPort()) };
    const companion: ?std.Io.net.Server = ipv6.listen(io_mod.getIo(), .{}) catch |err| switch (err) {
        error.AddressFamilyUnsupported, error.AddressUnavailable, error.ProtocolUnsupportedByAddressFamily => null,
        else => return err,
    };
    return .{ .ipv4 = primary, .ipv6 = companion };
}

fn pollBrowserToken(
    raw: ?*anyopaque,
    alloc: Allocator,
    transport: oauth_transport.Provider,
    metadata: oauth.Metadata,
    _: []const u8,
    _: []const u8,
    cancel_flag: *std.atomic.Value(bool),
    deadline: std.Io.Clock.Timestamp,
) !oauth.PollResult {
    if (comptime host_target.is_wasm) return error.ClaudeOAuthUnavailable;
    if (cancel_flag.load(.seq_cst)) return error.Cancelled;
    const context: *BrowserLoginContext = @ptrCast(@alignCast(raw.?));
    const manual_code = context.takeManualCode();
    defer if (manual_code) |code| secret.zeroAndFree(alloc, code);
    var accepted: ?browser_callback.Accepted(BrowserCallback) = null;
    defer if (accepted) |*callback| {
        callback.callback.deinit(alloc);
        callback.deinit();
    };
    const code = manual_code orelse code: {
        accepted = (try awaitBrowserCallback(
            alloc,
            &context.listeners,
            context.state,
            cancel_flag,
        )) orelse return .pending;
        break :code accepted.?.callback.code;
    };

    var token = exchangeAuthorizationCodeForRedirectWithBounds(
        alloc,
        transport,
        metadata.token_endpoint,
        code,
        context.code_verifier,
        context.redirect_uri,
        context.state,
        cancel_flag,
        deadline,
    ) catch |err| {
        if (accepted) |*callback| callback.respond(.failed) catch |response_err| {
            debug_trace.logf("auth", "Claude failure response failed err={s}", .{@errorName(response_err)});
        };
        return err;
    };
    errdefer token.deinit(alloc);

    const result = try oauth.takeBrowserPollResult(alloc, &token);
    context.pending_callback = accepted;
    accepted = null;
    return result;
}

const BrowserCallbackParserContext = struct {
    expected_state: []const u8,
};

fn awaitBrowserCallback(
    alloc: Allocator,
    listeners: *BrowserListeners,
    expected_state: []const u8,
    cancel_flag: *std.atomic.Value(bool),
) !?browser_callback.Accepted(BrowserCallback) {
    var parser_context = BrowserCallbackParserContext{ .expected_state = expected_state };
    if (try browser_callback.await(BrowserCallback, classifyBrowserCallback, alloc, &listeners.ipv4, &parser_context, cancel_flag, null)) |accepted| {
        return accepted;
    }
    const ipv6 = if (listeners.ipv6) |*listener| listener else return null;
    return browser_callback.await(BrowserCallback, classifyBrowserCallback, alloc, ipv6, &parser_context, cancel_flag, null);
}

fn classifyBrowserCallback(
    raw: ?*anyopaque,
    alloc: Allocator,
    target: []const u8,
) browser_callback.ParseResult(BrowserCallback) {
    const context: *BrowserCallbackParserContext = @ptrCast(@alignCast(raw.?));
    const callback = parseBrowserCallbackTarget(alloc, target, context.expected_state) catch |err| switch (err) {
        error.InvalidClaudeOAuthCallback, error.ClaudeOAuthStateMismatch => return .unrelated,
        else => return .{ .failed = err },
    };
    return .{ .accepted = callback };
}

fn completeSignIn(
    _: ?*anyopaque,
    alloc: Allocator,
    transport: oauth_transport.Provider,
    _: []const u8,
    _: []const u8,
    token: *oauth.TokenSet,
) !login_flow.SignInCompletion {
    return .{ .claude = try takeSession(alloc, transport, token) };
}

fn takeSession(alloc: Allocator, transport: oauth_transport.Provider, token: *oauth.TokenSet) !claude_session.Session {
    const refresh_token = token.refresh_token orelse return error.ClaudeRefreshTokenMissing;
    const expires_at_ms = oauth.expiryTimestampMs(io_mod.milliTimestamp(), token.expires_in) catch
        return error.InvalidClaudeOAuthResponse;
    const account_id = try fetchAccountId(alloc, transport, token.access_token, false);
    const session: claude_session.Session = .{
        .access_token = token.access_token,
        .refresh_token = refresh_token,
        .expires_at_ms = expires_at_ms,
        .account_id = account_id,
    };
    token.access_token = &.{};
    token.refresh_token = null;
    return session;
}

fn saveSignIn(_: ?*anyopaque, alloc: Allocator, completion: login_flow.SignInCompletion) !void {
    const session = switch (completion) {
        .claude => |session| session,
        else => return error.InvalidSignInCompletion,
    };
    try claude_session.saveNewSession(alloc, session);
}

fn finishSignIn(raw: ?*anyopaque, alloc: Allocator, saved: bool) void {
    const context: *BrowserLoginContext = @ptrCast(@alignCast(raw.?));
    context.finishCallback(alloc, saved);
}

pub fn runLogin(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    url_opener: host.UrlOpener,
) !void {
    if (comptime host_target.is_wasm) return error.ClaudeOAuthUnavailable;
    var runtime: login_flow.SignInRuntime = .{};
    defer runtime.deinit(alloc);
    if (!try startSignIn(&runtime, alloc, transport)) return error.ClaudeLoginBusy;

    const authorization_url = (try runtime.browserUrlAlloc(alloc)) orelse
        return error.ClaudeAuthorizationUrlMissing;
    defer alloc.free(authorization_url);
    try writeStdout("Open this URL to sign in with Claude:\n");
    try writeStdout(authorization_url);
    try writeStdout("\n\nWaiting for browser authorization...\n");
    try writeStdout("Paste the final URL, code#state, or authorization code and press Enter if the browser cannot return.\n");
    if (io_mod.getenv("FX_NO_OPEN_BROWSER") == null) {
        _ = url_opener.open(alloc, authorization_url) catch false;
    }

    var stdin_code: StdinManualCodeReader = .{};
    defer stdin_code.deinit();
    while (true) {
        if (try stdin_code.poll()) |code| {
            _ = try runtime.submitManualCode(alloc, code);
            stdin_code.clear();
        }
        switch (runtime.pollTransition(alloc)) {
            .none => try io_mod.getIo().sleep(.fromMilliseconds(50), .awake),
            .succeeded => |completion| {
                var owned = completion;
                defer owned.deinit(alloc);
                return;
            },
            .failed => |err| return err,
            .cancelled => return error.Cancelled,
        }
    }
}

const StdinManualCodeReader = struct {
    buffer: [login_flow.max_manual_code_bytes]u8 = undefined,
    len: usize = 0,
    closed: bool = false,

    fn poll(self: *StdinManualCodeReader) !?[]const u8 {
        if (self.closed) return null;
        var fds = [_]std.posix.pollfd{.{
            .fd = std.posix.STDIN_FILENO,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = try std.posix.poll(&fds, 0);
        if (ready == 0 or
            (fds[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) == 0) return null;

        var chunk: [512]u8 = undefined;
        defer @memset(&chunk, 0);
        const read_len = try std.posix.read(std.posix.STDIN_FILENO, &chunk);
        if (read_len == 0) {
            self.closed = true;
            return if (self.len == 0) null else self.buffer[0..self.len];
        }
        const line_end = std.mem.findScalar(u8, chunk[0..read_len], '\n') orelse read_len;
        if (line_end > self.buffer.len - self.len) return error.ClaudeAuthorizationCodeTooLong;
        @memcpy(self.buffer[self.len..][0..line_end], chunk[0..line_end]);
        self.len += line_end;
        if (line_end < read_len) {
            self.closed = true;
            return self.buffer[0..self.len];
        }
        return null;
    }

    fn clear(self: *StdinManualCodeReader) void {
        @memset(self.buffer[0..self.len], 0);
        self.len = 0;
    }

    fn deinit(self: *StdinManualCodeReader) void {
        @memset(&self.buffer, 0);
        self.* = undefined;
    }
};

/// Deletes only the saved fx Claude session. Does not contact Anthropic or
/// affect any other sign-in on this machine.
pub fn logoutLocally() !claude_session.DeleteOutcome {
    var mutation = (try claude_session.beginExistingMutation()) orelse return .missing;
    defer mutation.deinit();
    return mutation.delete();
}

pub fn sourceExists(alloc: Allocator) !bool {
    var session = (try claude_session.load(alloc)) orelse return false;
    defer session.deinit(alloc);
    return true;
}

pub fn loadAccess(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    mode: RefreshMode,
) !?Access {
    if (mode == .stored) {
        var session = (try claude_session.load(alloc)) orelse return null;
        defer session.deinit(alloc);
        return takeAccess(&session);
    }

    var mutation = (try claude_session.beginExistingMutation()) orelse return null;
    defer mutation.deinit();
    var session = (try mutation.load(alloc)) orelse return null;
    defer session.deinit(alloc);

    const expired = claude_session.refreshDeadlineMs(session.expires_at_ms) <= io_mod.milliTimestamp();
    const rotate = switch (mode) {
        .if_needed, .stored => expired,
        .force => true,
        .replace_rejected => |rejected| oauth.rejectedLoginRotates(session.access_token, rejected, expired),
    };
    if (rotate) {
        try refreshSession(alloc, transport, &mutation, &session);
    } else if (mode == .replace_rejected) {
        debug_trace.logf("auth", "Claude refresh skipped reason=saved_login_replaced", .{});
    }
    return takeAccess(&session);
}

fn takeAccess(session: *claude_session.Session) Access {
    const access_token = session.access_token;
    session.access_token = &.{};
    const account_id = session.account_id;
    session.account_id = &.{};
    return .{
        .access_token = access_token,
        .account_id = account_id,
        .refresh_after_ms = claude_session.refreshDeadlineMs(session.expires_at_ms),
    };
}

fn refreshSession(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    mutation: *claude_session.Mutation,
    session: *claude_session.Session,
) !void {
    try mutation.requireWritable();
    const payload = try jsonObjectPayload(alloc, .{
        .grant_type = "refresh_token",
        .client_id = client_id,
        .refresh_token = session.refresh_token,
    });
    defer secret.zeroAndFree(alloc, payload);
    // Each request has its whole budget from a fresh stamp, so another fx
    // waits for this one however slowly Anthropic answers.
    mutation.restamp();
    var token = requestRefreshToken(alloc, transport, payload) catch |err| switch (err) {
        error.CredentialRefreshRejected,
        error.InvalidClaudeOAuthResponse,
        => {
            debug_trace.logf("auth", "retiring terminal Claude session reason={s}", .{@errorName(err)});
            try retireRefreshSession(mutation);
            return error.CredentialRefreshRejected;
        },
        else => return err,
    };
    defer token.deinit(alloc);

    // The replacement asks Anthropic for the account the new token belongs to.
    mutation.restamp();
    var replacement = refreshReplacement(alloc, transport, &token, session.*) catch |err| {
        if (err == error.OutOfMemory) return err;
        debug_trace.logf("auth", "retiring unusable Claude refresh reason={s}", .{@errorName(err)});
        try retireRefreshSession(mutation);
        if (err == error.ClaudeAccountChanged) return err;
        return error.CredentialRefreshRejected;
    };
    errdefer replacement.deinit(alloc);
    mutation.save(alloc, replacement) catch |err| {
        debug_trace.logf("auth", "retiring Claude session after refresh save failed err={s}", .{@errorName(err)});
        retireRefreshSession(mutation) catch |cleanup_err| {
            debug_trace.logf("auth", "Claude session retirement failed err={s}", .{@errorName(cleanup_err)});
        };
        return error.CredentialRefreshPersistenceUncertain;
    };

    session.deinit(alloc);
    session.* = replacement;
    replacement.access_token = &.{};
    replacement.refresh_token = &.{};
    replacement.account_id = &.{};
}

fn refreshReplacement(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    token: *RefreshTokenResponse,
    current: claude_session.Session,
) !claude_session.Session {
    const account_id = try fetchAccountId(alloc, transport, token.access_token, true);
    errdefer alloc.free(account_id);
    if (!std.mem.eql(u8, account_id, current.account_id)) {
        return error.ClaudeAccountChanged;
    }
    const expires_in = token.expires_in orelse return error.InvalidClaudeOAuthResponse;
    const expires_at_ms = oauth.expiryTimestampMs(io_mod.milliTimestamp(), expires_in) catch
        return error.InvalidClaudeOAuthResponse;
    const refresh_token = token.refresh_token orelse try alloc.dupe(u8, current.refresh_token);
    const replacement = claude_session.Session{
        .access_token = token.access_token,
        .refresh_token = refresh_token,
        .expires_at_ms = expires_at_ms,
        .account_id = account_id,
    };
    token.access_token = &.{};
    if (token.refresh_token != null) token.refresh_token = null;
    return replacement;
}

fn retireRefreshSession(mutation: *claude_session.Mutation) !void {
    const outcome = mutation.delete() catch return error.CredentialRefreshPersistenceUncertain;
    if (outcome == .deleted_not_durable) return error.CredentialRefreshPersistenceUncertain;
}

const RefreshTokenResponse = struct {
    access_token: []u8,
    refresh_token: ?[]u8,
    expires_in: ?i64,

    fn deinit(self: *RefreshTokenResponse, alloc: Allocator) void {
        secret.zeroAndFree(alloc, self.access_token);
        if (self.refresh_token) |token| secret.zeroAndFree(alloc, token);
        self.* = undefined;
    }
};

fn requestRefreshToken(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    payload: []const u8,
) !RefreshTokenResponse {
    const endpoint_url = try configuredEndpoint(alloc, e2e_token_url_env, refresh_url);
    defer alloc.free(endpoint_url);
    var response = try transport.execute(alloc, .{
        .method = .post_json,
        .url = endpoint_url,
        .payload = payload,
        .outlives_cancel = true,
    });
    defer response.deinit(alloc);
    if (response.disposition != .accepted) {
        debug_trace.logf("auth", "Claude refresh request rejected", .{});
        if (try isInvalidGrant(alloc, response.body)) {
            return error.CredentialRefreshRejected;
        }
        return error.ClaudeOAuthRequestFailed;
    }
    const bytes = response.takeBody();
    defer secret.zeroAndFree(alloc, bytes);
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidClaudeOAuthResponse,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidClaudeOAuthResponse;
    const object = parsed.value.object;
    const access_token = try dupeRequiredString(alloc, object, "access_token");
    errdefer secret.zeroAndFree(alloc, access_token);
    const refresh_token = if (object.get("refresh_token")) |value| blk: {
        if (value != .string or value.string.len == 0) return error.InvalidClaudeOAuthResponse;
        break :blk try alloc.dupe(u8, value.string);
    } else null;
    errdefer if (refresh_token) |token| secret.zeroAndFree(alloc, token);
    const expires_in = if (object.get("expires_in")) |value| blk: {
        if (value != .integer or value.integer <= 0) return error.InvalidClaudeOAuthResponse;
        break :blk value.integer;
    } else null;
    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_in = expires_in,
    };
}

fn isInvalidGrant(alloc: Allocator, bytes: []const u8) !bool {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return false,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return false;
    const value = parsed.value.object.get("error") orelse return false;
    return value == .string and std.mem.eql(u8, value.string, "invalid_grant");
}

fn exchangeAuthorizationCodeForRedirectWithBounds(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    endpoint_url: []const u8,
    authorization_code: []const u8,
    code_verifier: []const u8,
    redirect_uri: []const u8,
    state: []const u8,
    cancel_flag: ?*std.atomic.Value(bool),
    deadline: ?std.Io.Clock.Timestamp,
) !oauth.BrowserTokenSet {
    const payload = try jsonObjectPayload(alloc, .{
        .grant_type = "authorization_code",
        .code = authorization_code,
        .state = state,
        .code_verifier = code_verifier,
        .redirect_uri = redirect_uri,
        .client_id = client_id,
    });
    defer secret.zeroAndFree(alloc, payload);
    return requestTokenAtWithBounds(alloc, transport, endpoint_url, payload, cancel_flag, deadline);
}
fn requestTokenAtWithBounds(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    endpoint_url: []const u8,
    payload: []const u8,
    cancel_flag: ?*std.atomic.Value(bool),
    deadline: ?std.Io.Clock.Timestamp,
) !oauth.BrowserTokenSet {
    const bytes = try requestAcceptedWithBounds(
        alloc,
        transport,
        .post_json,
        endpoint_url,
        payload,
        cancel_flag,
        deadline,
    );
    defer secret.zeroAndFree(alloc, bytes);
    return oauth.parseBrowserTokenSet(alloc, bytes) catch |err| switch (err) {
        error.InvalidOAuthResponse => return error.InvalidClaudeOAuthResponse,
        else => return err,
    };
}

fn configuredEndpoint(alloc: Allocator, env_name: []const u8, default_url: []const u8) ![]u8 {
    return oauth.configuredEndpoint(alloc, env_name, default_url) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidE2EClaudeEndpoint,
    };
}

fn fetchAccountId(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    access_token: []const u8,
    outlives_cancel: bool,
) ![]u8 {
    const endpoint_url = try configuredEndpoint(alloc, e2e_userinfo_url_env, userinfo_url);
    defer alloc.free(endpoint_url);
    const authorization = try alloc.print("Bearer {s}", .{access_token});
    defer secret.zeroAndFree(alloc, authorization);
    var response = try transport.execute(alloc, .{
        .method = .get,
        .url = endpoint_url,
        .authorization = authorization,
        .extra_headers = &oauth_api_headers,
        .outlives_cancel = outlives_cancel,
    });
    defer response.deinit(alloc);
    if (response.disposition != .accepted) {
        debug_trace.logf("auth", "Claude userinfo request rejected", .{});
        return error.ClaudeUserInfoRequestFailed;
    }
    return accountIdFromProfileJson(alloc, response.body) catch |err| {
        debug_trace.logf("auth", "Claude userinfo parse failed err={s}", .{@errorName(err)});
        return err;
    };
}

fn accountIdFromProfileJson(alloc: Allocator, bytes: []const u8) ![]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidClaudeUserInfoResponse,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidClaudeUserInfoResponse;
    return accountIdFromProfileObject(alloc, parsed.value.object);
}

fn accountIdFromProfileObject(alloc: Allocator, object: std.json.ObjectMap) ![]u8 {
    if (try nestedAccountId(alloc, object, "account")) |account_id| return account_id;
    if (try optionalProfileId(alloc, object, "sub")) |account_id| return account_id;
    if (try optionalProfileId(alloc, object, "uuid")) |account_id| return account_id;
    if (try nestedAccountId(alloc, object, "organization")) |account_id| return account_id;
    return error.InvalidClaudeUserInfoResponse;
}

fn nestedAccountId(alloc: Allocator, object: std.json.ObjectMap, key: []const u8) !?[]u8 {
    const value = object.get(key) orelse return null;
    if (value != .object) return error.InvalidClaudeUserInfoResponse;
    if (try optionalProfileId(alloc, value.object, "uuid")) |account_id| return account_id;
    if (try optionalProfileId(alloc, value.object, "id")) |account_id| return account_id;
    return error.InvalidClaudeUserInfoResponse;
}

fn optionalProfileId(alloc: Allocator, object: std.json.ObjectMap, key: []const u8) !?[]u8 {
    const value = object.get(key) orelse return null;
    if (value != .string or value.string.len == 0) return error.InvalidClaudeUserInfoResponse;
    if (!claude_session.validAccountId(value.string)) return error.InvalidClaudeUserInfoResponse;
    return try alloc.dupe(u8, value.string);
}

fn requestAcceptedWithBounds(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    method: oauth_transport.Method,
    url: []const u8,
    payload: []const u8,
    cancel_flag: ?*std.atomic.Value(bool),
    deadline: ?std.Io.Clock.Timestamp,
) ![]u8 {
    if (cancel_flag) |flag| if (flag.load(.seq_cst)) return error.Cancelled;
    var response = try transport.execute(alloc, .{
        .method = method,
        .url = url,
        .payload = payload,
        .cancel_flag = cancel_flag,
        .deadline = deadline,
    });
    defer response.deinit(alloc);
    if (response.disposition != .accepted) {
        debug_trace.logf("auth", "Claude OAuth request rejected", .{});
        return error.ClaudeOAuthRequestFailed;
    }
    return response.takeBody();
}

fn jsonObjectPayload(alloc: Allocator, value: anytype) ![]u8 {
    var body: std.Io.Writer.Allocating = .init(alloc);
    errdefer body.deinit();
    try std.json.Stringify.value(value, .{}, &body.writer);
    return body.toOwnedSlice();
}

fn dupeRequiredString(alloc: Allocator, object: std.json.ObjectMap, key: []const u8) ![]u8 {
    const value = object.get(key) orelse return error.InvalidClaudeOAuthResponse;
    if (value != .string or value.string.len == 0) return error.InvalidClaudeOAuthResponse;
    return alloc.dupe(u8, value.string);
}

const BrowserCallback = struct {
    code: []u8,

    fn deinit(self: *BrowserCallback, alloc: Allocator) void {
        secret.zeroAndFree(alloc, self.code);
        self.* = undefined;
    }
};

fn buildBrowserAuthorizationUrl(
    alloc: Allocator,
    authorize: []const u8,
    redirect_uri: []const u8,
    code_challenge: []const u8,
    state: []const u8,
) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    try out.writer.print("{s}?", .{std.mem.trimEnd(u8, authorize, "/")});
    var form: oauth.FormBody = .{};
    try form.append(&out.writer, "code", "true");
    try form.append(&out.writer, "response_type", "code");
    try form.append(&out.writer, "client_id", client_id);
    try form.append(&out.writer, "redirect_uri", redirect_uri);
    try form.append(&out.writer, "scope", browser_scope);
    try form.append(&out.writer, "code_challenge", code_challenge);
    try form.append(&out.writer, "code_challenge_method", "S256");
    try form.append(&out.writer, "state", state);
    return out.toOwnedSlice();
}

fn parsePastedAuthorizationInput(alloc: Allocator, input: []const u8, expected_state: []const u8) !BrowserCallback {
    const trimmed = std.mem.trim(u8, input, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len > login_flow.max_manual_code_bytes) return error.InvalidClaudeOAuthCallback;

    if (std.mem.find(u8, trimmed, "code=") != null) {
        const query_start = if (std.mem.findScalar(u8, trimmed, '?')) |index| index + 1 else 0;
        const query = trimmed[query_start..];
        const query_only = if (std.mem.findScalar(u8, query, '#')) |index| query[0..index] else query;
        const code = try queryValueAlloc(alloc, query_only, "code");
        errdefer secret.zeroAndFree(alloc, code);
        const maybe_state: ?[]u8 = oauth.queryValueNonEmptyAlloc(alloc, query_only, "state") catch |err| switch (err) {
            error.MissingQueryParameter => null,
            error.OutOfMemory => return err,
            else => return error.InvalidClaudeOAuthCallback,
        };
        if (maybe_state) |state| {
            defer secret.zeroAndFree(alloc, state);
            if (!std.mem.eql(u8, state, expected_state)) return error.ClaudeOAuthStateMismatch;
        }
        return .{ .code = code };
    }

    if (std.mem.findScalar(u8, trimmed, '#')) |index| {
        const code_part = trimmed[0..index];
        const state_part = trimmed[index + 1 ..];
        if (code_part.len == 0) return error.InvalidClaudeOAuthCallback;
        if (!std.mem.eql(u8, state_part, expected_state)) return error.ClaudeOAuthStateMismatch;
        return .{ .code = try alloc.dupe(u8, code_part) };
    }

    return .{ .code = try alloc.dupe(u8, trimmed) };
}

fn parseBrowserCallbackTarget(
    alloc: Allocator,
    target: []const u8,
    expected_state: []const u8,
) !BrowserCallback {
    const prefix = browser_callback_path ++ "?";
    if (!std.mem.startsWith(u8, target, prefix) or std.mem.findScalar(u8, target, '#') != null) {
        return error.InvalidClaudeOAuthCallback;
    }
    const query = target[prefix.len..];
    const code = try queryValueAlloc(alloc, query, "code");
    errdefer secret.zeroAndFree(alloc, code);
    const state = try queryValueAlloc(alloc, query, "state");
    defer secret.zeroAndFree(alloc, state);
    if (!std.mem.eql(u8, state, expected_state)) return error.ClaudeOAuthStateMismatch;
    return .{ .code = code };
}
fn queryValueAlloc(alloc: Allocator, query: []const u8, key: []const u8) ![]u8 {
    return oauth.queryValueNonEmptyAlloc(alloc, query, key) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.InvalidClaudeOAuthCallback,
    };
}

fn writeStdout(text: []const u8) !void {
    try std.Io.File.stdout().writeStreamingAll(io_mod.getIo(), text);
}

test "Claude E2E OAuth endpoint overrides accept only loopback HTTP" {
    try std.testing.expect(oauth.isLoopbackHttpUrl("http://127.0.0.1:1234/token"));
    try std.testing.expect(oauth.isLoopbackHttpUrl("http://localhost:1234/token"));
    try std.testing.expect(!oauth.isLoopbackHttpUrl("https://127.0.0.1:1234/token"));
    try std.testing.expect(!oauth.isLoopbackHttpUrl("http://example.com:1234/token"));
}

test "Claude browser authorization URL uses PKCE against the Claude authorize endpoint" {
    const url = try buildBrowserAuthorizationUrl(
        std.testing.allocator,
        "https://claude.ai/oauth/authorize",
        browser_redirect_uri,
        "challenge-value",
        "state-value",
    );
    defer std.testing.allocator.free(url);

    try std.testing.expect(std.mem.startsWith(u8, url, "https://claude.ai/oauth/authorize?"));
    try std.testing.expect(std.mem.find(u8, url, "code=true") != null);
    try std.testing.expect(std.mem.find(u8, url, "response_type=code") != null);
    try std.testing.expect(std.mem.find(u8, url, "code_challenge=challenge-value") != null);
    try std.testing.expect(std.mem.find(u8, url, "code_challenge_method=S256") != null);
    try std.testing.expect(std.mem.find(u8, url, "state=state-value") != null);
    try std.testing.expect(std.mem.find(u8, url, "redirect_uri=http%3A%2F%2Flocalhost%3A54545%2Fcallback") != null);
    try std.testing.expect(std.mem.find(u8, url, "127.0.0.1") == null);
    // Claude Code scopes are user-scoped; the issuer rejects OpenID scopes.
    try std.testing.expect(std.mem.find(u8, url, "scope=user%3Aprofile") != null);
    try std.testing.expect(std.mem.find(u8, url, "user%3Ainference") != null);
    try std.testing.expect(std.mem.find(u8, url, "openid") == null);
    try std.testing.expect(std.mem.find(u8, url, "email") == null);
}

test "Claude pasted authorization input accepts code#state and callback URLs" {
    var from_pair = try parsePastedAuthorizationInput(
        std.testing.allocator,
        "  auth-code#state-value\n",
        "state-value",
    );
    defer from_pair.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("auth-code", from_pair.code);

    var from_url = try parsePastedAuthorizationInput(
        std.testing.allocator,
        "https://console.anthropic.com/oauth/code/callback?code=auth%20code&state=state-value",
        "state-value",
    );
    defer from_url.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("auth code", from_url.code);

    var from_raw = try parsePastedAuthorizationInput(
        std.testing.allocator,
        "raw-code",
        "state-value",
    );
    defer from_raw.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("raw-code", from_raw.code);

    try std.testing.expectError(
        error.ClaudeOAuthStateMismatch,
        parsePastedAuthorizationInput(
            std.testing.allocator,
            "auth-code#other",
            "state-value",
        ),
    );
}

test "Claude browser callback requires the exact path and state" {
    var callback = try parseBrowserCallbackTarget(
        std.testing.allocator,
        "/callback?code=auth%20code&state=expected",
        "expected",
    );
    defer callback.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("auth code", callback.code);

    try std.testing.expectError(
        error.ClaudeOAuthStateMismatch,
        parseBrowserCallbackTarget(
            std.testing.allocator,
            "/callback?code=auth&state=other",
            "expected",
        ),
    );
    try std.testing.expectError(
        error.InvalidClaudeOAuthCallback,
        parseBrowserCallbackTarget(
            std.testing.allocator,
            "/other?code=auth&state=expected",
            "expected",
        ),
    );
}

test "Claude account identity prefers nested profile uuid and sends oauth headers" {
    const State = struct {
        authorization_seen: bool = false,
        saw_version: bool = false,
        saw_beta: bool = false,

        fn execute(raw: ?*anyopaque, alloc: Allocator, request: oauth_transport.Request) !oauth_transport.Response {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            self.authorization_seen = std.mem.eql(u8, request.authorization orelse "", "Bearer access-token");
            for (request.extra_headers) |header| {
                if (std.mem.eql(u8, header.name, "anthropic-version") and
                    std.mem.eql(u8, header.value, anthropic_api_version))
                {
                    self.saw_version = true;
                }
                if (std.mem.eql(u8, header.name, "anthropic-beta") and
                    std.mem.eql(u8, header.value, oauth_beta))
                {
                    self.saw_beta = true;
                }
            }
            return .{
                .disposition = .accepted,
                .body = try alloc.dupe(u8, "{\"account\":{\"uuid\":\"acct_test\"},\"organization\":{\"uuid\":\"org_test\"}}"),
            };
        }
    };
    var state = State{};
    const account_id = try fetchAccountId(
        std.testing.allocator,
        .{ .context = &state, .execute_fn = State.execute },
        "access-token",
        false,
    );
    defer std.testing.allocator.free(account_id);
    try std.testing.expect(state.authorization_seen);
    try std.testing.expect(state.saw_version);
    try std.testing.expect(state.saw_beta);
    try std.testing.expectEqualStrings("acct_test", account_id);
}

test "Claude account identity accepts OIDC sub when account uuid is absent" {
    const State = struct {
        fn execute(_: ?*anyopaque, alloc: Allocator, _: oauth_transport.Request) !oauth_transport.Response {
            return .{ .disposition = .accepted, .body = try alloc.dupe(u8, "{\"sub\":\"acct_oidc\"}") };
        }
    };
    const account_id = try fetchAccountId(
        std.testing.allocator,
        .{ .execute_fn = State.execute },
        "access-token",
        false,
    );
    defer std.testing.allocator.free(account_id);
    try std.testing.expectEqualStrings("acct_oidc", account_id);
}

test "Claude token exchange uses JSON with state and omits API headers" {
    const State = struct {
        method: ?oauth_transport.Method = null,
        payload: [1024]u8 = undefined,
        payload_len: usize = 0,
        extra_header_count: usize = 0,

        fn execute(raw: ?*anyopaque, alloc: Allocator, request: oauth_transport.Request) !oauth_transport.Response {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const payload = request.payload orelse &.{};
            self.method = request.method;
            self.payload_len = @min(payload.len, self.payload.len);
            @memcpy(self.payload[0..self.payload_len], payload[0..self.payload_len]);
            self.extra_header_count = request.extra_headers.len;
            return .{
                .disposition = .accepted,
                .body = try alloc.dupe(u8, "{\"access_token\":\"access\",\"refresh_token\":\"refresh\",\"expires_in\":3600}"),
            };
        }
    };
    var state = State{};
    var token = try exchangeAuthorizationCodeForRedirectWithBounds(
        std.testing.allocator,
        .{ .context = &state, .execute_fn = State.execute },
        "http://127.0.0.1:1/token",
        "auth-code",
        "verifier",
        browser_redirect_uri,
        "state-value",
        null,
        null,
    );
    defer token.deinit(std.testing.allocator);

    try std.testing.expectEqual(oauth_transport.Method.post_json, state.method.?);
    try std.testing.expectEqual(@as(usize, 0), state.extra_header_count);
    const payload = state.payload[0..state.payload_len];
    try std.testing.expect(std.mem.find(u8, payload, "\"grant_type\":\"authorization_code\"") != null);
    try std.testing.expect(std.mem.find(u8, payload, "\"code\":\"auth-code\"") != null);
    try std.testing.expect(std.mem.find(u8, payload, "\"state\":\"state-value\"") != null);
    try std.testing.expect(std.mem.find(u8, payload, "\"client_id\":\"") != null);
    try std.testing.expect(std.mem.find(u8, payload, "\"code_verifier\":\"verifier\"") != null);
    try std.testing.expect(std.mem.find(u8, payload, "grant_type=authorization_code") == null);
    try std.testing.expectEqualStrings("access", token.access_token);
}

test "Claude refresh uses JSON" {
    const State = struct {
        method: ?oauth_transport.Method = null,
        payload: [512]u8 = undefined,
        payload_len: usize = 0,

        fn execute(raw: ?*anyopaque, alloc: Allocator, request: oauth_transport.Request) !oauth_transport.Response {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            const payload = request.payload orelse &.{};
            self.method = request.method;
            self.payload_len = @min(payload.len, self.payload.len);
            @memcpy(self.payload[0..self.payload_len], payload[0..self.payload_len]);
            return .{
                .disposition = .accepted,
                .body = try alloc.dupe(u8, "{\"access_token\":\"new-access\",\"expires_in\":3600}"),
            };
        }
    };
    var state = State{};
    var response = try requestRefreshToken(
        std.testing.allocator,
        .{ .context = &state, .execute_fn = State.execute },
        "{\"grant_type\":\"refresh_token\",\"client_id\":\"client\",\"refresh_token\":\"[redacted]\"}",
    );
    defer response.deinit(std.testing.allocator);

    try std.testing.expectEqual(oauth_transport.Method.post_json, state.method.?);
    try std.testing.expect(std.mem.find(u8, state.payload[0..state.payload_len], "\"grant_type\":\"refresh_token\"") != null);
    try std.testing.expect(response.refresh_token == null);
    try std.testing.expectEqual(@as(?i64, 3600), response.expires_in);
}

test "Claude account identity rejects unsafe userinfo bytes" {
    const State = struct {
        fn execute(_: ?*anyopaque, alloc: Allocator, _: oauth_transport.Request) !oauth_transport.Response {
            return .{ .disposition = .accepted, .body = try alloc.dupe(u8, "{\"account\":{\"uuid\":\"acct\\ninjected\"}}") };
        }
    };
    try std.testing.expectError(
        error.InvalidClaudeUserInfoResponse,
        fetchAccountId(
            std.testing.allocator,
            .{ .execute_fn = State.execute },
            "access-token",
            false,
        ),
    );
}

test "Claude refresh skips an already-replaced login and retires a rejected grant" {
    const alloc = std.testing.allocator;
    const testing = @import("stored_login_testing.zig");
    const Stub = struct {
        calls: usize = 0,

        fn execute(raw: ?*anyopaque, gpa: Allocator, request: oauth_transport.Request) !oauth_transport.Response {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            self.calls += 1;
            try std.testing.expectEqual(oauth_transport.Method.post_json, request.method);
            try std.testing.expect(request.outlives_cancel);
            return .{ .disposition = .rejected, .body = try gpa.dupe(u8, "{\"error\":\"invalid_grant\"}") };
        }
    };
    var home: testing.StoredLoginHome = undefined;
    try home.install(alloc);
    defer home.deinit();
    var stub: Stub = .{};
    const transport: oauth_transport.Provider = .{ .context = &stub, .execute_fn = Stub.execute };

    var access_token = "current".*;
    var refresh_token = "refresh".*;
    var account_id = "account".*;
    try claude_session.saveNewSession(alloc, .{
        .access_token = &access_token,
        .refresh_token = &refresh_token,
        .account_id = &account_id,
        .expires_at_ms = testing.far_future_ms,
    });
    var access = (try loadAccess(alloc, transport, .{ .replace_rejected = "previous" })) orelse
        return error.TestUnexpectedResult;
    defer access.deinit(alloc);
    try std.testing.expectEqualStrings("current", access.access_token);
    try std.testing.expectEqual(@as(usize, 0), stub.calls);

    try std.testing.expectError(error.CredentialRefreshRejected, loadAccess(alloc, transport, .{ .replace_rejected = "current" }));
    try std.testing.expectEqual(@as(usize, 1), stub.calls);
    try std.testing.expect(!try sourceExists(alloc));
}

test "Claude logout deletes locally without needing a usable token" {
    const alloc = std.testing.allocator;
    const testing = @import("stored_login_testing.zig");
    var home: testing.StoredLoginHome = undefined;
    try home.install(alloc);
    defer home.deinit();
    try home.tmp.dir.writeFile(std.testing.io, .{
        .sub_path = ".fx/" ++ claude_session.auth_file_name,
        .data = "unreadable auth data",
        .flags = .{ .permissions = std.Io.File.Permissions.fromMode(0o600) },
    });
    try std.testing.expectEqual(claude_session.DeleteOutcome.deleted, try logoutLocally());
    try std.testing.expectEqual(claude_session.DeleteOutcome.missing, try logoutLocally());
}

test "Claude refresh stores the replacement only for the same account" {
    const alloc = std.testing.allocator;
    const testing = @import("stored_login_testing.zig");
    const Stub = struct {
        account: []const u8 = "account",

        fn execute(raw: ?*anyopaque, gpa: Allocator, request: oauth_transport.Request) !oauth_transport.Response {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            try std.testing.expect(request.outlives_cancel);
            return switch (request.method) {
                .post_json => .{ .disposition = .accepted, .body = try gpa.dupe(u8, "{\"access_token\":\"new\",\"expires_in\":3600}") },
                .get => .{ .disposition = .accepted, .body = try jsonObjectPayload(gpa, .{ .sub = self.account }) },
                else => error.TestUnexpectedResult,
            };
        }
    };
    var home: testing.StoredLoginHome = undefined;
    try home.install(alloc);
    defer home.deinit();
    var stub: Stub = .{};
    const transport: oauth_transport.Provider = .{ .context = &stub, .execute_fn = Stub.execute };
    var access_token = "old".*;
    var refresh_token = "refresh".*;
    var account_id = "account".*;
    try claude_session.saveNewSession(alloc, .{
        .access_token = &access_token,
        .refresh_token = &refresh_token,
        .account_id = &account_id,
        .expires_at_ms = 100_000,
    });
    var access = (try loadAccess(alloc, transport, .if_needed)) orelse return error.TestUnexpectedResult;
    defer access.deinit(alloc);
    try std.testing.expectEqualStrings("new", access.access_token);
    var saved = (try claude_session.load(alloc)) orelse return error.TestUnexpectedResult;
    defer saved.deinit(alloc);
    try std.testing.expectEqualStrings("new", saved.access_token);
    try std.testing.expectEqualStrings("refresh", saved.refresh_token);

    stub.account = "different";
    try std.testing.expectError(error.ClaudeAccountChanged, loadAccess(alloc, transport, .force));
    try std.testing.expect(!try sourceExists(alloc));
}
