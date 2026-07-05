//! D-Bus introspection XML parser: turns a <node>/<interface>/<method>/<signal>/
//! <property> document into an in-memory model. Hand-rolled tag scanner (same
//! style as the daemon's busconfig parser); no XML dependency. The returned
//! Document owns an arena backing every model string.

const std = @import("std");

pub const Direction = enum { in_, out };

pub const Arg = struct {
    name: []const u8,
    sig: []const u8,
    dir: Direction,
};

pub const Method = struct {
    name: []const u8,
    args: []Arg,

    pub fn inArgs(self: Method, buf: *std.ArrayList(Arg), gpa: std.mem.Allocator) !void {
        for (self.args) |a| if (a.dir == .in_) try buf.append(gpa, a);
    }
};

pub const Signal = struct {
    name: []const u8,
    args: []Arg,
};

pub const Property = struct {
    name: []const u8,
    sig: []const u8,
    access: []const u8,
};

pub const Interface = struct {
    name: []const u8,
    methods: []Method,
    signals: []Signal,
    properties: []Property,
};

pub const Node = struct {
    interfaces: []Interface,
};

pub const Document = struct {
    arena: std.heap.ArenaAllocator,
    node: Node,

    pub fn deinit(self: *Document) void {
        self.arena.deinit();
    }
};

pub const Error = error{Malformed} || std.mem.Allocator.Error;

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
    i += 1;
    while (i < attrs.len and std.ascii.isWhitespace(attrs[i])) i += 1;
    if (i >= attrs.len) return null;
    const q = attrs[i];
    if (q != '"' and q != '\'') return null;
    i += 1;
    const vs = i;
    while (i < attrs.len and attrs[i] != q) i += 1;
    if (i >= attrs.len) return null;
    return .{ .key = key, .val = attrs[vs..i], .next = i + 1 };
}

fn attr(attrs: []const u8, key: []const u8) ?[]const u8 {
    var i: usize = 0;
    while (nextAttr(attrs, i)) |a| {
        if (std.mem.eql(u8, a.key, key)) return a.val;
        i = a.next;
    }
    return null;
}

pub fn parse(gpa: std.mem.Allocator, xml: []const u8) Error!Document {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const a = arena.allocator();

    var interfaces: std.ArrayList(Interface) = .empty;
    var cur_iface: ?struct {
        name: []const u8,
        methods: std.ArrayList(Method),
        signals: std.ArrayList(Signal),
        properties: std.ArrayList(Property),
    } = null;
    var cur_method: ?struct { name: []const u8, args: std.ArrayList(Arg) } = null;
    var cur_signal: ?struct { name: []const u8, args: std.ArrayList(Arg) } = null;

    var i: usize = 0;
    while (i < xml.len) {
        if (xml[i] != '<') {
            i += 1;
            continue;
        }
        if (std.mem.startsWith(u8, xml[i..], "<!--")) {
            const e = std.mem.indexOf(u8, xml[i..], "-->") orelse return Error.Malformed;
            i += e + 3;
            continue;
        }
        if (i + 1 < xml.len and (xml[i + 1] == '!' or xml[i + 1] == '?')) {
            const e = std.mem.indexOfScalarPos(u8, xml, i, '>') orelse return Error.Malformed;
            i = e + 1;
            continue;
        }
        const close = std.mem.indexOfScalarPos(u8, xml, i, '>') orelse return Error.Malformed;
        const inner = xml[i + 1 .. close];
        i = close + 1;
        if (inner.len == 0) continue;

        if (inner[0] == '/') {
            const name = std.mem.trim(u8, inner[1..], " \t\r\n");
            if (std.mem.eql(u8, name, "method")) {
                if (cur_method) |*m| {
                    if (cur_iface) |*iface| try iface.methods.append(a, .{ .name = m.name, .args = try m.args.toOwnedSlice(a) });
                    cur_method = null;
                }
            } else if (std.mem.eql(u8, name, "signal")) {
                if (cur_signal) |*s| {
                    if (cur_iface) |*iface| try iface.signals.append(a, .{ .name = s.name, .args = try s.args.toOwnedSlice(a) });
                    cur_signal = null;
                }
            } else if (std.mem.eql(u8, name, "interface")) {
                if (cur_iface) |*iface| {
                    try interfaces.append(a, .{
                        .name = iface.name,
                        .methods = try iface.methods.toOwnedSlice(a),
                        .signals = try iface.signals.toOwnedSlice(a),
                        .properties = try iface.properties.toOwnedSlice(a),
                    });
                    cur_iface = null;
                }
            }
            continue;
        }

        const self_closing = inner[inner.len - 1] == '/';
        const body = if (self_closing) inner[0 .. inner.len - 1] else inner;
        var s: usize = 0;
        while (s < body.len and !std.ascii.isWhitespace(body[s])) s += 1;
        const name = body[0..s];
        const attrs = body[s..];

        if (std.mem.eql(u8, name, "interface")) {
            const nm = attr(attrs, "name") orelse return Error.Malformed;
            cur_iface = .{ .name = try a.dupe(u8, nm), .methods = .empty, .signals = .empty, .properties = .empty };
        } else if (std.mem.eql(u8, name, "method")) {
            const nm = attr(attrs, "name") orelse return Error.Malformed;
            if (self_closing) {
                if (cur_iface) |*iface| try iface.methods.append(a, .{ .name = try a.dupe(u8, nm), .args = &.{} });
            } else {
                cur_method = .{ .name = try a.dupe(u8, nm), .args = .empty };
            }
        } else if (std.mem.eql(u8, name, "signal")) {
            const nm = attr(attrs, "name") orelse return Error.Malformed;
            if (self_closing) {
                if (cur_iface) |*iface| try iface.signals.append(a, .{ .name = try a.dupe(u8, nm), .args = &.{} });
            } else {
                cur_signal = .{ .name = try a.dupe(u8, nm), .args = .empty };
            }
        } else if (std.mem.eql(u8, name, "arg")) {
            const sig = attr(attrs, "type") orelse return Error.Malformed;
            const dir_s = attr(attrs, "direction") orelse "out";
            const arg_name = attr(attrs, "name") orelse "";
            const arg = Arg{
                .name = try a.dupe(u8, arg_name),
                .sig = try a.dupe(u8, sig),
                .dir = if (std.mem.eql(u8, dir_s, "in")) .in_ else .out,
            };
            if (cur_method) |*m| {
                try m.args.append(a, arg);
            } else if (cur_signal) |*sg| {
                try sg.args.append(a, arg);
            }
        } else if (std.mem.eql(u8, name, "property")) {
            const nm = attr(attrs, "name") orelse return Error.Malformed;
            const sig = attr(attrs, "type") orelse return Error.Malformed;
            const access = attr(attrs, "access") orelse "read";
            if (cur_iface) |*iface| try iface.properties.append(a, .{
                .name = try a.dupe(u8, nm),
                .sig = try a.dupe(u8, sig),
                .access = try a.dupe(u8, access),
            });
        }
    }

    return .{ .arena = arena, .node = .{ .interfaces = try interfaces.toOwnedSlice(a) } };
}

const testing = std.testing;

test "parse an introspection document" {
    const xml =
        \\<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
        \\<node>
        \\  <interface name="org.example.Calc">
        \\    <method name="Add">
        \\      <arg name="a" type="i" direction="in"/>
        \\      <arg name="b" type="i" direction="in"/>
        \\      <arg name="sum" type="i" direction="out"/>
        \\    </method>
        \\    <method name="Reset"/>
        \\    <signal name="Changed">
        \\      <arg name="value" type="i"/>
        \\    </signal>
        \\    <property name="Total" type="x" access="read"/>
        \\  </interface>
        \\</node>
    ;
    var doc = try parse(testing.allocator, xml);
    defer doc.deinit();

    try testing.expectEqual(@as(usize, 1), doc.node.interfaces.len);
    const iface = doc.node.interfaces[0];
    try testing.expectEqualStrings("org.example.Calc", iface.name);
    try testing.expectEqual(@as(usize, 2), iface.methods.len);

    const add = iface.methods[0];
    try testing.expectEqualStrings("Add", add.name);
    try testing.expectEqual(@as(usize, 3), add.args.len);
    try testing.expectEqual(Direction.in_, add.args[0].dir);
    try testing.expectEqualStrings("i", add.args[0].sig);
    try testing.expectEqual(Direction.out, add.args[2].dir);

    try testing.expectEqualStrings("Reset", iface.methods[1].name);
    try testing.expectEqual(@as(usize, 0), iface.methods[1].args.len);

    try testing.expectEqual(@as(usize, 1), iface.signals.len);
    try testing.expectEqualStrings("Changed", iface.signals[0].name);
    try testing.expectEqual(@as(usize, 1), iface.properties.len);
    try testing.expectEqualStrings("Total", iface.properties[0].name);
    try testing.expectEqualStrings("x", iface.properties[0].sig);
}
