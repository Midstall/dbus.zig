//! Minimal busconfig parser (the D-Bus daemon's system.conf / session.conf).
//! Hand-rolled for the subset we use: <type>, <servicedir>, and <policy> blocks
//! with <allow>/<deny> rules. No XML dependency; files are read via raw syscalls.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const Error = error{ Malformed, OpenFailed, ReadFailed } || std.mem.Allocator.Error;

pub const RuleKind = enum { allow, deny };

pub const Rule = struct {
    kind: RuleKind,
    send_destination: ?[]const u8 = null,
    send_interface: ?[]const u8 = null,
    send_member: ?[]const u8 = null,
    receive_sender: ?[]const u8 = null,
    own: ?[]const u8 = null,
    own_prefix: ?[]const u8 = null,
};

pub const PolicyContext = enum { default, mandatory, user, group };

pub const Policy = struct {
    context: PolicyContext,
    principal: ?[]const u8 = null, // the user or group name, when context is user/group
    rules: std.ArrayList(Rule) = .empty,
};

pub const Config = struct {
    gpa: std.mem.Allocator,
    bus_type: ?[]const u8 = null,
    servicedirs: std.ArrayList([]const u8) = .empty,
    policies: std.ArrayList(Policy) = .empty,

    pub fn deinit(self: *Config) void {
        if (self.bus_type) |t| self.gpa.free(t);
        for (self.servicedirs.items) |s| self.gpa.free(s);
        self.servicedirs.deinit(self.gpa);
        for (self.policies.items) |*p| {
            if (p.principal) |s| self.gpa.free(s);
            for (p.rules.items) |*r| freeRule(self.gpa, r);
            p.rules.deinit(self.gpa);
        }
        self.policies.deinit(self.gpa);
    }
};

fn freeRule(gpa: std.mem.Allocator, r: *Rule) void {
    inline for (.{ r.send_destination, r.send_interface, r.send_member, r.receive_sender, r.own, r.own_prefix }) |m| {
        if (m) |s| gpa.free(s);
    }
}

/// Read one `key="value"` (or `key='value'`) attribute starting at `attrs[i..]`.
const Attr = struct { key: []const u8, val: []const u8, next: usize };

fn nextAttr(attrs: []const u8, start: usize) ?Attr {
    var i = start;
    while (i < attrs.len and std.ascii.isWhitespace(attrs[i])) i += 1;
    if (i >= attrs.len or attrs[i] == '/' or attrs[i] == '>') return null;
    const key_start = i;
    while (i < attrs.len and attrs[i] != '=' and !std.ascii.isWhitespace(attrs[i])) i += 1;
    const key = attrs[key_start..i];
    while (i < attrs.len and attrs[i] != '=') i += 1;
    if (i >= attrs.len) return null;
    i += 1; // '='
    while (i < attrs.len and std.ascii.isWhitespace(attrs[i])) i += 1;
    if (i >= attrs.len) return null;
    const quote = attrs[i];
    if (quote != '"' and quote != '\'') return null;
    i += 1;
    const val_start = i;
    while (i < attrs.len and attrs[i] != quote) i += 1;
    if (i >= attrs.len) return null;
    const val = attrs[val_start..i];
    return .{ .key = key, .val = val, .next = i + 1 };
}

fn attrValue(gpa: std.mem.Allocator, attrs: []const u8, key: []const u8) Error!?[]u8 {
    var i: usize = 0;
    while (nextAttr(attrs, i)) |a| {
        if (std.mem.eql(u8, a.key, key)) return try gpa.dupe(u8, a.val);
        i = a.next;
    }
    return null;
}

fn buildRule(gpa: std.mem.Allocator, kind: RuleKind, attrs: []const u8) Error!Rule {
    var r = Rule{ .kind = kind };
    errdefer freeRule(gpa, &r);
    r.send_destination = try attrValue(gpa, attrs, "send_destination");
    r.send_interface = try attrValue(gpa, attrs, "send_interface");
    r.send_member = try attrValue(gpa, attrs, "send_member");
    r.receive_sender = try attrValue(gpa, attrs, "receive_sender");
    r.own = try attrValue(gpa, attrs, "own");
    r.own_prefix = try attrValue(gpa, attrs, "own_prefix");
    return r;
}

/// Parse a busconfig document.
pub fn parse(gpa: std.mem.Allocator, xml: []const u8) Error!Config {
    var cfg = Config{ .gpa = gpa };
    errdefer cfg.deinit();

    var cur: ?Policy = null;
    errdefer if (cur) |*p| {
        if (p.principal) |s| gpa.free(s);
        for (p.rules.items) |*r| freeRule(gpa, r);
        p.rules.deinit(gpa);
    };

    var i: usize = 0;
    while (i < xml.len) {
        if (xml[i] != '<') {
            i += 1;
            continue;
        }
        // Skip comments, doctype, and PIs.
        if (std.mem.startsWith(u8, xml[i..], "<!--")) {
            const end = std.mem.indexOf(u8, xml[i..], "-->") orelse return Error.Malformed;
            i += end + 3;
            continue;
        }
        if (i + 1 < xml.len and (xml[i + 1] == '!' or xml[i + 1] == '?')) {
            const end = std.mem.indexOfScalarPos(u8, xml, i, '>') orelse return Error.Malformed;
            i = end + 1;
            continue;
        }
        const close = std.mem.indexOfScalarPos(u8, xml, i, '>') orelse return Error.Malformed;
        const inner = xml[i + 1 .. close]; // tag contents without < >
        i = close + 1;

        if (inner.len == 0) continue;
        if (inner[0] == '/') {
            // End tag.
            const name = std.mem.trim(u8, inner[1..], " \t\r\n");
            if (std.mem.eql(u8, name, "policy")) {
                if (cur) |p| {
                    try cfg.policies.append(gpa, p);
                    cur = null;
                }
            }
            continue;
        }

        // Start (or self-closing) tag: split name and attributes.
        const self_closing = inner[inner.len - 1] == '/';
        const body = if (self_closing) inner[0 .. inner.len - 1] else inner;
        var s: usize = 0;
        while (s < body.len and !std.ascii.isWhitespace(body[s])) s += 1;
        const name = body[0..s];
        const attrs = body[s..];

        if (std.mem.eql(u8, name, "policy")) {
            var p = Policy{ .context = .default };
            if (try attrValue(gpa, attrs, "context")) |c| {
                defer gpa.free(c);
                if (std.mem.eql(u8, c, "mandatory")) p.context = .mandatory;
            }
            if (try attrValue(gpa, attrs, "user")) |u| {
                p.context = .user;
                p.principal = u;
            } else if (try attrValue(gpa, attrs, "group")) |g| {
                p.context = .group;
                p.principal = g;
            }
            cur = p;
        } else if (std.mem.eql(u8, name, "allow") or std.mem.eql(u8, name, "deny")) {
            if (cur) |*p| {
                const kind: RuleKind = if (name[0] == 'a') .allow else .deny;
                const rule = try buildRule(gpa, kind, attrs);
                try p.rules.append(gpa, rule);
            }
        } else if (std.mem.eql(u8, name, "type")) {
            const text_end = std.mem.indexOfScalarPos(u8, xml, i, '<') orelse xml.len;
            cfg.bus_type = try gpa.dupe(u8, std.mem.trim(u8, xml[i..text_end], " \t\r\n"));
            i = text_end;
        } else if (std.mem.eql(u8, name, "servicedir")) {
            const text_end = std.mem.indexOfScalarPos(u8, xml, i, '<') orelse xml.len;
            try cfg.servicedirs.append(gpa, try gpa.dupe(u8, std.mem.trim(u8, xml[i..text_end], " \t\r\n")));
            i = text_end;
        }
    }
    // A trailing unclosed (or self-closing) <policy> would otherwise leak.
    if (cur) |p| {
        try cfg.policies.append(gpa, p);
        cur = null;
    }
    return cfg;
}

/// Read and parse a busconfig file via raw syscalls.
pub fn parseFile(gpa: std.mem.Allocator, path: []const u8) Error!Config {
    var pbuf: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len + 1 > pbuf.len) return Error.OpenFailed;
    @memcpy(pbuf[0..path.len], path);
    pbuf[path.len] = 0;
    const rc = linux.openat(linux.AT.FDCWD, @ptrCast(&pbuf), .{ .ACCMODE = .RDONLY }, 0);
    if (posix.errno(rc) != .SUCCESS) return Error.OpenFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(gpa);
    var buf: [4096]u8 = undefined;
    while (true) {
        const n = posix.read(fd, &buf) catch return Error.ReadFailed;
        if (n == 0) break;
        try data.appendSlice(gpa, buf[0..n]);
    }
    return parse(gpa, data.items);
}

const testing = std.testing;

test "parse a busconfig with type, policy, and servicedir" {
    const xml =
        \\<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
        \\<busconfig>
        \\  <type>session</type>
        \\  <servicedir>/usr/share/dbus-1/services</servicedir>
        \\  <policy context="default">
        \\    <allow own="*"/>
        \\    <allow send_destination="org.freedesktop.DBus"/>
        \\    <deny send_interface="org.example.Secret"/>
        \\  </policy>
        \\  <policy user="root">
        \\    <allow send_destination="com.root.Only"/>
        \\  </policy>
        \\</busconfig>
    ;
    var cfg = try parse(testing.allocator, xml);
    defer cfg.deinit();

    try testing.expectEqualStrings("session", cfg.bus_type.?);
    try testing.expectEqual(@as(usize, 1), cfg.servicedirs.items.len);
    try testing.expectEqualStrings("/usr/share/dbus-1/services", cfg.servicedirs.items[0]);
    try testing.expectEqual(@as(usize, 2), cfg.policies.items.len);

    const def = cfg.policies.items[0];
    try testing.expectEqual(PolicyContext.default, def.context);
    try testing.expectEqual(@as(usize, 3), def.rules.items.len);
    try testing.expectEqualStrings("*", def.rules.items[0].own.?);
    try testing.expectEqual(RuleKind.deny, def.rules.items[2].kind);
    try testing.expectEqualStrings("org.example.Secret", def.rules.items[2].send_interface.?);

    const usr = cfg.policies.items[1];
    try testing.expectEqual(PolicyContext.user, usr.context);
    try testing.expectEqualStrings("root", usr.principal.?);
}
