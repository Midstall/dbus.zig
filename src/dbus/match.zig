//! D-Bus match rules: the `key='value'` expressions a client registers with the
//! bus (AddMatch) to receive signals, and the local predicate used to route a
//! received message to the right handler. See the spec's "Match Rules" section.

const std = @import("std");
const message = @import("message.zig");
const Message = message.Message;
const unmarshal = @import("unmarshal.zig");

pub const Error = error{ InvalidRule, UnknownType } || std.mem.Allocator.Error;

pub const MatchRule = struct {
    msg_type: ?message.MessageType = null,
    sender: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    path: ?[]const u8 = null,
    path_namespace: ?[]const u8 = null,
    destination: ?[]const u8 = null,
    arg0: ?[]const u8 = null,

    /// Free the string fields. Only call on a rule produced by `parse`, whose
    /// values are heap-allocated; inline-built rules borrow their strings.
    pub fn deinitOwned(self: MatchRule, gpa: std.mem.Allocator) void {
        inline for (.{ self.sender, self.interface, self.member, self.path, self.path_namespace, self.destination, self.arg0 }) |m| {
            if (m) |s| gpa.free(s);
        }
    }

    /// Serialize to the AddMatch wire form: comma-joined `key='value'`, with any
    /// `'` in a value escaped as `'\''`.
    pub fn toString(self: MatchRule, gpa: std.mem.Allocator) Error![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(gpa);
        var first = true;
        if (self.msg_type) |t| try appendPair(gpa, &out, &first, "type", typeName(t));
        if (self.sender) |v| try appendPair(gpa, &out, &first, "sender", v);
        if (self.interface) |v| try appendPair(gpa, &out, &first, "interface", v);
        if (self.member) |v| try appendPair(gpa, &out, &first, "member", v);
        if (self.path) |v| try appendPair(gpa, &out, &first, "path", v);
        if (self.path_namespace) |v| try appendPair(gpa, &out, &first, "path_namespace", v);
        if (self.destination) |v| try appendPair(gpa, &out, &first, "destination", v);
        if (self.arg0) |v| try appendPair(gpa, &out, &first, "arg0", v);
        return out.toOwnedSlice(gpa);
    }

    /// True if `msg` satisfies every present field of this rule.
    pub fn matches(self: MatchRule, msg: *const Message) bool {
        if (self.msg_type) |t| if (msg.msg_type != t) return false;
        if (self.sender) |v| if (!eqOpt(msg.sender, v)) return false;
        if (self.interface) |v| if (!eqOpt(msg.interface, v)) return false;
        if (self.member) |v| if (!eqOpt(msg.member, v)) return false;
        if (self.path) |v| if (!eqOpt(msg.path, v)) return false;
        if (self.destination) |v| if (!eqOpt(msg.destination, v)) return false;
        if (self.path_namespace) |ns| {
            const p = msg.path orelse return false;
            if (!pathUnder(p, ns)) return false;
        }
        if (self.arg0) |a| {
            const got = firstStringArg(msg) orelse return false;
            if (!std.mem.eql(u8, got, a)) return false;
        }
        return true;
    }
};

fn eqOpt(actual: ?[]const u8, want: []const u8) bool {
    const a = actual orelse return false;
    return std.mem.eql(u8, a, want);
}

fn pathUnder(p: []const u8, ns: []const u8) bool {
    if (std.mem.eql(u8, p, ns)) return true;
    if (std.mem.eql(u8, ns, "/")) return true;
    return p.len > ns.len and std.mem.startsWith(u8, p, ns) and p[ns.len] == '/';
}

fn firstStringArg(msg: *const Message) ?[]const u8 {
    const sig = msg.body_signature orelse return null;
    if (sig.len == 0) return null;
    // Plain arg0 matches STRING arguments only (object paths use arg0path).
    if (sig[0] != 's') return null;
    var r = unmarshal.Reader.init(msg.body, msg.endian);
    return r.string() catch null;
}

fn typeName(t: message.MessageType) []const u8 {
    return switch (t) {
        .method_call => "method_call",
        .method_return => "method_return",
        .error_ => "error",
        .signal => "signal",
    };
}

fn typeFromName(s: []const u8) ?message.MessageType {
    if (std.mem.eql(u8, s, "method_call")) return .method_call;
    if (std.mem.eql(u8, s, "method_return")) return .method_return;
    if (std.mem.eql(u8, s, "error")) return .error_;
    if (std.mem.eql(u8, s, "signal")) return .signal;
    return null;
}

fn appendPair(gpa: std.mem.Allocator, out: *std.ArrayList(u8), first: *bool, key: []const u8, val: []const u8) Error!void {
    if (!first.*) try out.append(gpa, ',');
    first.* = false;
    try out.appendSlice(gpa, key);
    try out.appendSlice(gpa, "='");
    for (val) |c| {
        if (c == '\'') try out.appendSlice(gpa, "'\\''") else try out.append(gpa, c);
    }
    try out.append(gpa, '\'');
}

/// Parse an AddMatch-form rule string. Values may be single-quoted with `'\''`
/// escapes, or bare (up to the next comma). Returned strings are heap-allocated;
/// release with `deinitOwned`.
pub fn parse(gpa: std.mem.Allocator, s: []const u8) Error!MatchRule {
    var rule = MatchRule{};
    errdefer rule.deinitOwned(gpa);

    var i: usize = 0;
    while (i < s.len) {
        // key
        const key_start = i;
        while (i < s.len and s[i] != '=') : (i += 1) {}
        if (i >= s.len) return Error.InvalidRule;
        const key = s[key_start..i];
        i += 1; // skip '='

        // value
        var val: std.ArrayList(u8) = .empty;
        defer val.deinit(gpa);
        if (i < s.len and s[i] == '\'') {
            i += 1; // opening quote
            while (i < s.len) {
                if (s[i] == '\'') {
                    // Either end of value, or the 4-char "'\''" escape for a
                    // literal quote (close, backslash, quote, reopen).
                    if (i + 3 < s.len and s[i + 1] == '\\' and s[i + 2] == '\'' and s[i + 3] == '\'') {
                        try val.append(gpa, '\'');
                        i += 4;
                        continue;
                    }
                    i += 1; // closing quote
                    break;
                }
                try val.append(gpa, s[i]);
                i += 1;
            }
        } else {
            while (i < s.len and s[i] != ',') : (i += 1) try val.append(gpa, s[i]);
        }

        try assign(gpa, &rule, key, val.items);

        if (i < s.len and s[i] == ',') i += 1;
    }
    return rule;
}

fn assign(gpa: std.mem.Allocator, rule: *MatchRule, key: []const u8, val: []const u8) Error!void {
    if (std.mem.eql(u8, key, "type")) {
        rule.msg_type = typeFromName(val) orelse return Error.UnknownType;
    } else if (std.mem.eql(u8, key, "sender")) {
        rule.sender = try gpa.dupe(u8, val);
    } else if (std.mem.eql(u8, key, "interface")) {
        rule.interface = try gpa.dupe(u8, val);
    } else if (std.mem.eql(u8, key, "member")) {
        rule.member = try gpa.dupe(u8, val);
    } else if (std.mem.eql(u8, key, "path")) {
        rule.path = try gpa.dupe(u8, val);
    } else if (std.mem.eql(u8, key, "path_namespace")) {
        rule.path_namespace = try gpa.dupe(u8, val);
    } else if (std.mem.eql(u8, key, "destination")) {
        rule.destination = try gpa.dupe(u8, val);
    } else if (std.mem.eql(u8, key, "arg0")) {
        rule.arg0 = try gpa.dupe(u8, val);
    }
    // Unknown keys are ignored.
}

const testing = std.testing;

test "toString builds the AddMatch form" {
    const rule = MatchRule{ .msg_type = .signal, .interface = "org.freedesktop.DBus", .member = "NameOwnerChanged" };
    const s = try rule.toString(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expectEqualStrings("type='signal',interface='org.freedesktop.DBus',member='NameOwnerChanged'", s);
}

test "toString escapes single quotes" {
    const rule = MatchRule{ .arg0 = "a'b" };
    const s = try rule.toString(testing.allocator);
    defer testing.allocator.free(s);
    try testing.expectEqualStrings("arg0='a'\\''b'", s);
}

test "parse round-trips a rule" {
    var rule = try parse(testing.allocator, "type='signal',interface='a.b.C',member='Sig'");
    defer rule.deinitOwned(testing.allocator);
    try testing.expectEqual(message.MessageType.signal, rule.msg_type.?);
    try testing.expectEqualStrings("a.b.C", rule.interface.?);
    try testing.expectEqualStrings("Sig", rule.member.?);
}

test "parse handles the '\\'' escape" {
    var rule = try parse(testing.allocator, "arg0='a'\\''b'");
    defer rule.deinitOwned(testing.allocator);
    try testing.expectEqualStrings("a'b", rule.arg0.?);
}

test "matches on type, interface, member, path_namespace" {
    const rule = MatchRule{ .msg_type = .signal, .interface = "a.b", .path_namespace = "/org/x" };
    const yes = Message{ .msg_type = .signal, .serial = 1, .path = "/org/x/y", .interface = "a.b", .member = "M" };
    const no_iface = Message{ .msg_type = .signal, .serial = 1, .path = "/org/x/y", .interface = "a.c", .member = "M" };
    const no_path = Message{ .msg_type = .signal, .serial = 1, .path = "/org/y", .interface = "a.b", .member = "M" };
    try testing.expect(rule.matches(&yes));
    try testing.expect(!rule.matches(&no_iface));
    try testing.expect(!rule.matches(&no_path));
}

test "matches on arg0 string" {
    const marshal = @import("marshal.zig");
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &body, .little);
    try w.string(":1.5");

    const msg = Message{ .msg_type = .signal, .serial = 1, .path = "/", .interface = "a.b", .member = "M", .body_signature = "s", .body = body.items };
    try testing.expect((MatchRule{ .arg0 = ":1.5" }).matches(&msg));
    try testing.expect(!(MatchRule{ .arg0 = ":1.6" }).matches(&msg));
}
