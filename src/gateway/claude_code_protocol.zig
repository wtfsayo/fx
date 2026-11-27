const std = @import("std");

// Wire conventions documented by pi-black's Claude Code 2.1.332 adapter.
const version = "2.1.332";
pub const user_agent = "claude-cli/" ++ version ++ " (external, sdk-cli)";
const sdk_instruction = "You are a Claude agent, built on Anthropic's Claude Agent SDK.";
const billing_prefix = "x-anthropic-billing-header: ";
const cch_placeholder = "cch=00000";
const cch_seed: u64 = 0x4d659218e32a3268;
const hex = "0123456789abcdef";
const Value = std.json.Value;
const Allocator = std.mem.Allocator;

/// Returns an owned request with SDK system blocks and ephemeral cache breakpoints.
pub fn prepare(alloc: Allocator, payload: []const u8) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    const scratch = arena.allocator();
    var body = try std.json.parseFromSliceLeaky(Value, scratch, payload, .{ .parse_numbers = false });
    if (body != .object) return error.InvalidClaudeWireRequest;
    const fingerprint = try promptFingerprint(scratch, try firstUserPrompt(scratch, body));
    const billing = try scratch.print(billing_prefix ++ "cc_version=" ++ version ++ ".{s}; cc_entrypoint=sdk-cli; " ++ cch_placeholder ++ ";", .{&fingerprint});
    var system = std.json.Array.init(scratch);
    try system.append(try textBlock(scratch, billing));
    try system.append(try textBlock(scratch, sdk_instruction));
    if (body.object.get("system")) |old_system| switch (old_system) {
        .string => |text| try system.append(try textBlock(scratch, text)),
        .array => |blocks| try system.appendSlice(blocks.items),
        else => return error.InvalidClaudeWireRequest,
    } else {
        try system.append(try textBlock(scratch, "You are a helpful assistant."));
    }
    try markCacheBreakpoint(scratch, &system.items[system.items.len - 1]);
    try body.object.put(scratch, "system", .{ .array = system });
    if (body.object.getPtr("tools")) |tools| {
        if (lastBlock(tools)) |tool| try markCacheBreakpoint(scratch, tool);
    }
    if (body.object.getPtr("messages")) |messages| {
        if (lastBlock(messages)) |message| {
            if (strEqual(message.object.get("role"), "user")) {
                if (message.object.getPtr("content")) |content| {
                    if (content.* == .string) {
                        var blocks = std.json.Array.init(scratch);
                        try blocks.append(try textBlock(scratch, content.string));
                        content.* = .{ .array = blocks };
                    }
                    if (lastBlock(content)) |block| {
                        const kind = block.object.get("type");
                        if (strEqual(kind, "text") or strEqual(kind, "image") or strEqual(kind, "tool_result")) {
                            try markCacheBreakpoint(scratch, block);
                        }
                    }
                }
            }
        }
    }
    return serializeAttested(alloc, scratch, &body);
}

fn lastBlock(value: *Value) ?*Value {
    if (value.* != .array or value.array.items.len == 0) return null;
    const last = &value.array.items[value.array.items.len - 1];
    return if (last.* == .object) last else null;
}

fn markCacheBreakpoint(alloc: Allocator, block: *Value) !void {
    if (block.* != .object) return error.InvalidClaudeWireRequest;
    var control: std.json.ObjectMap = .{};
    try control.put(alloc, "type", .{ .string = "ephemeral" });
    try block.object.put(alloc, "cache_control", .{ .object = control });
}

fn textBlock(alloc: Allocator, text: []const u8) !Value {
    var block: Value = .{ .object = .{} };
    try block.object.put(alloc, "type", .{ .string = "text" });
    try block.object.put(alloc, "text", .{ .string = text });
    return block;
}

fn firstUserPrompt(alloc: Allocator, body: Value) ![]const u8 {
    const messages = body.object.get("messages") orelse return "";
    if (messages != .array) return "";
    for (messages.array.items) |message| {
        if (message != .object or !strEqual(message.object.get("role"), "user")) continue;
        const content = message.object.get("content") orelse return "";
        switch (content) {
            .string => |text| return text,
            .array => |blocks| {
                var text: std.Io.Writer.Allocating = .init(alloc);
                errdefer text.deinit();
                for (blocks.items) |block| {
                    if (block != .object or !strEqual(block.object.get("type"), "text")) continue;
                    if (block.object.get("text")) |part| if (part == .string) try text.writer.writeAll(part.string);
                }
                return try text.toOwnedSlice();
            },
            else => return "",
        }
    }
    return "";
}

fn strEqual(value: ?Value, expected: []const u8) bool {
    const actual = value orelse return false;
    return actual == .string and std.mem.eql(u8, actual.string, expected);
}

fn promptFingerprint(alloc: Allocator, prompt: []const u8) ![3]u8 {
    const units = try std.unicode.utf8ToUtf16LeAlloc(alloc, prompt);
    defer alloc.free(units);
    var selected: [3]u16 = undefined;
    for ([_]usize{ 4, 7, 20 }, &selected) |index, *unit| {
        unit.* = if (index < units.len) units[index] else '0';
    }
    for (&selected, 0..) |*unit, index| {
        const value = std.mem.littleToNative(u16, unit.*);
        if (std.unicode.utf16IsHighSurrogate(value)) {
            if (index + 1 < selected.len and std.unicode.utf16IsLowSurrogate(std.mem.littleToNative(u16, selected[index + 1]))) continue;
        } else if (std.unicode.utf16IsLowSurrogate(value)) {
            if (index > 0 and std.unicode.utf16IsHighSurrogate(std.mem.littleToNative(u16, selected[index - 1]))) continue;
        } else continue;
        unit.* = std.mem.nativeToLittle(u16, 0xfffd);
    }
    const chars = try std.unicode.utf16LeToUtf8Alloc(alloc, &selected);
    defer alloc.free(chars);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("59cf53e54c78");
    hash.update(chars);
    hash.update(version);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ hex[digest[0] >> 4], hex[digest[0] & 15], hex[digest[1] >> 4] };
}

fn serializeAttested(alloc: Allocator, scratch: Allocator, body: *Value) ![]u8 {
    const system = body.object.get("system") orelse return error.InvalidClaudeWireRequest;
    if (system != .array or system.array.items.len == 0 or system.array.items[0] != .object) return error.InvalidClaudeWireRequest;
    const text = system.array.items[0].object.getPtr("text") orelse return error.InvalidClaudeWireRequest;
    if (text.* != .string or !std.mem.startsWith(u8, text.string, billing_prefix) or !std.mem.endsWith(u8, text.string, cch_placeholder ++ ";")) return error.InvalidClaudeWireRequest;
    const model = body.object.get("model") orelse return error.InvalidClaudeWireRequest;
    if (model != .string or !body.object.contains("max_tokens")) return error.InvalidClaudeWireRequest;

    var normalized: std.json.ObjectMap = .{};
    var iterator = body.object.iterator();
    while (iterator.next()) |entry| {
        const key = entry.key_ptr.*;
        if (std.mem.eql(u8, key, "max_tokens")) continue;
        try normalized.put(scratch, key, if (std.mem.eql(u8, key, "model")) .{ .string = "" } else entry.value_ptr.*);
    }
    const serialized = try std.json.Stringify.valueAlloc(scratch, Value{ .object = normalized }, .{});
    const cch = std.hash.XxHash64.hash(cch_seed, serialized) & 0xfffff;
    const billing = try scratch.dupe(u8, text.string);
    const offset = billing.len - 6;
    for (0..5) |i| billing[offset + i] = hex[@as(usize, @intCast((cch >> @as(u6, @intCast((4 - i) * 4))) & 15))];
    text.* = .{ .string = billing };
    return std.json.Stringify.valueAlloc(alloc, body.*, .{});
}

pub fn uuid(seed: [16]u8) [36]u8 {
    var bytes = seed;
    bytes[6] = bytes[6] & 0x0f | 0x40;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    const encoded = std.fmt.bytesToHex(bytes, .lower);
    return encoded[0..8].* ++ "-".* ++ encoded[8..12].* ++ "-".* ++ encoded[12..16].* ++ "-".* ++ encoded[16..20].* ++ "-".* ++ encoded[20..32].*;
}

test "Pi Black reference checksum matches, modifying only the billing block" {
    const alloc = std.testing.allocator;
    const fixture = "{\"model\":\"claude-opus-5\",\"messages\":[{\"role\":\"user\",\"content\":\"A\"}],\"max_tokens\":64000,\"stream\":true,\"system\":[{\"type\":\"text\",\"text\":\"x-anthropic-billing-header: cc_version=2.1.224.000; cc_entrypoint=sdk-cli; cch=00000;\"}]}";
    var arena = std.heap.ArenaAllocator.init(alloc);
    defer arena.deinit();
    var value = try std.json.parseFromSliceLeaky(Value, arena.allocator(), fixture, .{});
    const body = try serializeAttested(alloc, arena.allocator(), &value);
    defer alloc.free(body);
    try std.testing.expect(std.mem.find(u8, body, "cch=7ba34;") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"max_tokens\":64000") != null);
}

test "Claude SDK wire preparation preserves fx instructions and user placeholders" {
    const alloc = std.testing.allocator;
    const fixture = "{\"model\":\"claude-fable-5-2\",\"stream\":true,\"max_tokens\":8192,\"system\":[{\"type\":\"text\",\"text\":\"Keep fx permissions.\"}],\"messages\":[{\"role\":\"user\",\"content\":[{\"type\":\"text\",\"text\":\"hello cch=00000\"}]}]}";
    const body = try prepare(alloc, fixture);
    defer alloc.free(body);
    var parsed = try std.json.parseFromSlice(Value, alloc, body, .{});
    defer parsed.deinit();
    const object = parsed.value.object;
    const blocks = object.get("system").?.array.items;
    try std.testing.expectEqual(@as(usize, 3), blocks.len);
    try std.testing.expect(std.mem.startsWith(u8, blocks[0].object.get("text").?.string, billing_prefix));
    try std.testing.expectEqualStrings(sdk_instruction, blocks[1].object.get("text").?.string);
    try std.testing.expectEqualStrings("Keep fx permissions.", blocks[2].object.get("text").?.string);
    try std.testing.expect(std.mem.find(u8, body, "hello cch=00000") != null);
    try std.testing.expect(object.get("thinking") == null);
}

test "Claude cache breakpoints cover tools, stable instructions, and the newest tool result" {
    const alloc = std.testing.allocator;
    const fixture =
        \\{"model":"claude-fable-5-2","max_tokens":8192,"system":"Stable instructions",
        \\ "tools":[{"name":"first"},{"name":"last"}],
        \\ "messages":[{"role":"user","content":[{"type":"text","text":"First prompt"}]},
        \\ {"role":"assistant","content":[{"type":"tool_use","id":"call","name":"last","input":{}}]},
        \\ {"role":"user","content":[{"type":"tool_result","tool_use_id":"call","content":"Result"}]}]}
    ;
    const body = try prepare(alloc, fixture);
    defer alloc.free(body);
    var parsed = try std.json.parseFromSlice(Value, alloc, body, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 3), std.mem.count(u8, body, "\"cache_control\":{\"type\":\"ephemeral\"}"));
    const object = parsed.value.object;
    const tools = object.get("tools").?.array.items;
    try std.testing.expect(!tools[0].object.contains("cache_control"));
    try std.testing.expect(tools[1].object.contains("cache_control"));
    const system = object.get("system").?.array.items;
    try std.testing.expect(!system[0].object.contains("cache_control"));
    try std.testing.expect(!system[1].object.contains("cache_control"));
    try std.testing.expect(system[2].object.contains("cache_control"));
    const messages = object.get("messages").?.array.items;
    try std.testing.expect(!messages[0].object.get("content").?.array.items[0].object.contains("cache_control"));
    const result = messages[2].object.get("content").?.array.items[0];
    try std.testing.expect(result.object.contains("cache_control"));
    try std.testing.expectEqualStrings("Result", result.object.get("content").?.string);
}

test "request UUID formats the supplied seed" {
    try std.testing.expectEqualStrings("00000000-0000-4000-8000-000000000000", &uuid(@splat(0)));
}
