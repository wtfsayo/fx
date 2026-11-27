const std = @import("std");
const subscription_session = @import("subscription_session.zig");
const types = @import("../shared/types.zig");
const secret = @import("secret.zig");

pub const auth_file_name = "claude-auth.json";

const store = subscription_session.Store(.{
    .auth_file_name = auth_file_name,
    .mutation_lock_file_name = "claude-auth.lock",
    .trace_label = "Claude",
}, error.InvalidClaudeAuthSession, error.ClaudeOAuthUnavailable);

pub const Session = store.Session;
pub const Mutation = store.Mutation;
pub const DeleteOutcome = subscription_session.DeleteOutcome;
pub const presence = store.presence;
pub const requireSignInStorage = store.requireSignInStorage;
pub const load = store.load;
pub const saveNewSession = store.saveNewSession;
pub const beginExistingMutation = store.beginExistingMutation;
pub const validAccountId = types.validCredentialAccountId;

pub fn refreshDeadlineMs(expires_at_ms: i64) i64 {
    return subscription_session.refreshDeadlineMs(@max(expires_at_ms, 0));
}

test "Claude auth preserves the legacy v1 file format" {
    const alloc = std.testing.allocator;
    const fixture =
        \\{"version":1,"access_token":"access","refresh_token":"refresh","expires_at_ms":1234,"account_id":"acct_123"}
    ;
    var session = try store.parse(alloc, fixture);
    defer session.deinit(alloc);
    const encoded = try store.stringify(alloc, session);
    defer secret.zeroAndFree(alloc, encoded);
    try std.testing.expectEqualStrings(fixture ++ "\n", encoded);
    try std.testing.expectEqual(@as(i64, 40_000), refreshDeadlineMs(100_000));
    try std.testing.expectEqual(@as(i64, 0), refreshDeadlineMs(std.math.minInt(i64)));
}

test "Claude rejects an unsafe stored account identity" {
    const invalid =
        \\{"version":1,"access_token":"access","refresh_token":"refresh","expires_at_ms":1234,"account_id":"acct\ninjected"}
    ;
    try std.testing.expectError(error.InvalidClaudeAuthSession, store.parse(std.testing.allocator, invalid));
}
