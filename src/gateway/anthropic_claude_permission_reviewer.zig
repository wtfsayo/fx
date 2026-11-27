const std = @import("std");
const classifier = @import("../core/permissions/auto_classifier.zig");
const claude_session = @import("../core/auth/claude_session.zig");
const types = @import("../core/shared/types.zig");
const claude = @import("anthropic_claude.zig");
const reviewer = @import("responses_permission_reviewer.zig");

pub const provider: classifier.Provider = .{ .review_fn = reviewClaude };

fn reviewClaude(_: ?*anyopaque, alloc: std.mem.Allocator, input: classifier.ProviderInput, request: classifier.ReviewRequest) !classifier.ParseOutcome {
    if (input.credential_source != .claude_subscription) return .{ .invalid = .provider_context_missing };
    return reviewer.review(alloc, input, request, .{
        .source = .claude_subscription,
        .model = request.review_turn.model,
        .require_account = true,
        .validate_fn = validateCredential,
        .build_fn = claude.buildRequest,
        .send_fn = claude.streamPrepared,
    });
}

fn validateCredential(_: std.mem.Allocator, input: classifier.ProviderInput) !void {
    if (!claude.validToken(input.credential)) return error.InvalidClaudeSubscriptionCredential;
    if (!claude_session.validAccountId(input.account_id orelse return error.InvalidClaudeSubscriptionAccount)) {
        return error.InvalidClaudeSubscriptionAccount;
    }
}

test "Claude reviewer builds Messages with the admitted model and pending result" {
    const alloc = std.testing.allocator;
    const instructions = [_]types.ChatMessage{.{ .role = .system, .content = "Review only the pending action." }};
    const conversation = [_]types.ChatMessage{
        .{ .role = .user, .content = "User requested the change." },
        .{ .role = .assistant, .tool_calls = &.{.{ .id = "call_review", .name = "write_file", .arguments_json = "{\"path\":\"a.txt\"}" }} },
    };
    const model = "claude-sonnet-4-6";
    var cancel: std.atomic.Value(bool) = .init(false);
    const body = try reviewer.buildPayloadForTest(alloc, model, &instructions, &conversation, "call_review", std.Io.Clock.Timestamp.fromNow(std.testing.io, .{
        .clock = .awake,
        .raw = .fromSeconds(5),
    }), &cancel, claude.buildRequest);
    defer alloc.free(body);
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, body, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings(model, object.get("model").?.string);
    try std.testing.expectEqualStrings("any", object.get("tool_choice").?.object.get("type").?.string);
    try std.testing.expect(std.mem.find(u8, body, "\"type\":\"tool_result\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "Review only the pending action.") != null);
}
