//! The standard D-Bus interfaces exported on every object: org.freedesktop.DBus
//! .Peer (Ping, GetMachineId), .Introspectable (Introspect -> XML), and
//! .Properties (Get, GetAll). `Standard` holds the method tables with their
//! registry ctx at a stable address; register them on a path via `registerOn`.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const message = @import("message.zig");
const Message = message.Message;
const marshal = @import("marshal.zig");
const unmarshal = @import("unmarshal.zig");
const signature = @import("signature.zig");
const object = @import("object.zig");
const Registry = object.Registry;
const Interface = object.Interface;
const Method = object.Method;
const HandlerError = object.HandlerError;

fn ping(ctx: ?*anyopaque, call: *const Message, w: *marshal.Writer) HandlerError![]const u8 {
    _ = ctx;
    _ = call;
    _ = w;
    return ""; // empty reply
}

fn readMachineId(buf: []u8) ?[]const u8 {
    const paths = [_][:0]const u8{ "/etc/machine-id", "/var/lib/dbus/machine-id" };
    for (paths) |path| {
        const rc = linux.openat(linux.AT.FDCWD, path.ptr, .{ .ACCMODE = .RDONLY }, 0);
        if (posix.errno(rc) != .SUCCESS) continue;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);
        const n = posix.read(fd, buf) catch continue;
        const trimmed = std.mem.trim(u8, buf[0..n], " \t\r\n");
        if (trimmed.len > 0) return trimmed;
    }
    return null;
}

fn getMachineId(ctx: ?*anyopaque, call: *const Message, w: *marshal.Writer) HandlerError![]const u8 {
    _ = ctx;
    _ = call;
    var buf: [64]u8 = undefined;
    const id = readMachineId(&buf) orelse "00000000000000000000000000000000";
    try w.string(id);
    return "s";
}

fn appendArgs(gpa: std.mem.Allocator, out: *std.ArrayList(u8), sig: []const u8, dir: []const u8) HandlerError!void {
    var it = signature.Iterator.init(sig);
    while (it.next()) |t| {
        try out.appendSlice(gpa, "      <arg type=\"");
        try out.appendSlice(gpa, t);
        try out.appendSlice(gpa, "\" direction=\"");
        try out.appendSlice(gpa, dir);
        try out.appendSlice(gpa, "\"/>\n");
    }
}

fn introspect(ctx: ?*anyopaque, call: *const Message, w: *marshal.Writer) HandlerError![]const u8 {
    const registry: *Registry = @ptrCast(@alignCast(ctx.?));
    const path = call.path orelse return error.Failed;
    const gpa = w.gpa;

    var xml: std.ArrayList(u8) = .empty;
    defer xml.deinit(gpa);
    try xml.appendSlice(gpa,
        \\<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
        \\<node>
        \\
    );
    for (registry.interfacesFor(path)) |iface| {
        try xml.appendSlice(gpa, "  <interface name=\"");
        try xml.appendSlice(gpa, iface.name);
        try xml.appendSlice(gpa, "\">\n");
        for (iface.methods) |m| {
            try xml.appendSlice(gpa, "    <method name=\"");
            try xml.appendSlice(gpa, m.name);
            try xml.appendSlice(gpa, "\">\n");
            try appendArgs(gpa, &xml, m.in_sig, "in");
            try appendArgs(gpa, &xml, m.out_sig, "out");
            try xml.appendSlice(gpa, "    </method>\n");
        }
        for (iface.properties) |p| {
            try xml.appendSlice(gpa, "    <property name=\"");
            try xml.appendSlice(gpa, p.name);
            try xml.appendSlice(gpa, "\" type=\"");
            try xml.appendSlice(gpa, p.sig);
            try xml.appendSlice(gpa, "\" access=\"read\"/>\n");
        }
        try xml.appendSlice(gpa, "  </interface>\n");
    }
    try xml.appendSlice(gpa, "</node>\n");

    try w.string(xml.items);
    return "s";
}

fn findProperty(registry: *Registry, path: []const u8, iface_name: []const u8, prop_name: []const u8) ?object.Property {
    for (registry.interfacesFor(path)) |iface| {
        if (!std.mem.eql(u8, iface.name, iface_name)) continue;
        for (iface.properties) |p| {
            if (std.mem.eql(u8, p.name, prop_name)) return p;
        }
    }
    return null;
}

fn propGet(ctx: ?*anyopaque, call: *const Message, w: *marshal.Writer) HandlerError![]const u8 {
    const registry: *Registry = @ptrCast(@alignCast(ctx.?));
    const path = call.path orelse return error.Failed;
    var r = unmarshal.Reader.init(call.body, call.endian);
    const iface_name = r.string() catch return error.Failed;
    const prop_name = r.string() catch return error.Failed;
    const p = findProperty(registry, path, iface_name, prop_name) orelse return error.Failed;
    try w.beginVariant(p.sig);
    try p.getter(p.ctx, w);
    return "v";
}

fn propGetAll(ctx: ?*anyopaque, call: *const Message, w: *marshal.Writer) HandlerError![]const u8 {
    const registry: *Registry = @ptrCast(@alignCast(ctx.?));
    const path = call.path orelse return error.Failed;
    var r = unmarshal.Reader.init(call.body, call.endian);
    const iface_name = r.string() catch return error.Failed;

    const actx = try w.beginArray(8); // a{sv}: dict-entry alignment 8
    for (registry.interfacesFor(path)) |iface| {
        if (!std.mem.eql(u8, iface.name, iface_name)) continue;
        for (iface.properties) |p| {
            try w.beginStruct(); // dict-entry aligns to 8
            try w.string(p.name);
            try w.beginVariant(p.sig);
            try p.getter(p.ctx, w);
        }
    }
    w.endArray(actx);
    return "a{sv}";
}

/// Holds the standard-interface method tables with a stable address so their
/// borrowed slices stay valid. Construct once (e.g. owned by the Bus) and call
/// `registerOn` for each exported path.
pub const Standard = struct {
    peer_methods: [2]Method,
    introspectable_methods: [1]Method,
    properties_methods: [2]Method,

    pub fn init(registry: *Registry) Standard {
        return .{
            .peer_methods = .{
                .{ .name = "Ping", .handler = ping },
                .{ .name = "GetMachineId", .handler = getMachineId, .out_sig = "s" },
            },
            .introspectable_methods = .{
                .{ .name = "Introspect", .handler = introspect, .ctx = registry, .out_sig = "s" },
            },
            .properties_methods = .{
                .{ .name = "Get", .handler = propGet, .ctx = registry, .in_sig = "ss", .out_sig = "v" },
                .{ .name = "GetAll", .handler = propGetAll, .ctx = registry, .in_sig = "s", .out_sig = "a{sv}" },
            },
        };
    }

    pub fn peer(self: *const Standard) Interface {
        return .{ .name = "org.freedesktop.DBus.Peer", .methods = &self.peer_methods };
    }
    pub fn introspectable(self: *const Standard) Interface {
        return .{ .name = "org.freedesktop.DBus.Introspectable", .methods = &self.introspectable_methods };
    }
    pub fn properties(self: *const Standard) Interface {
        return .{ .name = "org.freedesktop.DBus.Properties", .methods = &self.properties_methods };
    }

    /// Register all three standard interfaces on `path`.
    pub fn registerOn(self: *const Standard, registry: *Registry, path: []const u8) object.Error!void {
        try registry.addInterface(path, self.peer());
        try registry.addInterface(path, self.introspectable());
        try registry.addInterface(path, self.properties());
    }
};

const testing = std.testing;

fn callMsg(path: []const u8, body: []const u8, sig: ?[]const u8) Message {
    return .{ .msg_type = .method_call, .serial = 1, .path = path, .member = "X", .body_signature = sig, .body = body, .endian = .little };
}

test "Peer.Ping returns an empty reply" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &buf, .little);
    const sig = try ping(null, &callMsg("/", "", null), &w);
    try testing.expectEqualStrings("", sig);
    try testing.expectEqual(@as(usize, 0), buf.items.len);
}

test "Peer.GetMachineId returns a string" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &buf, .little);
    const sig = try getMachineId(null, &callMsg("/", "", null), &w);
    try testing.expectEqualStrings("s", sig);
    var r = unmarshal.Reader.init(buf.items, .little);
    const id = try r.string();
    try testing.expect(id.len > 0);
}

test "Introspect emits XML for the registered interfaces" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    var std_ifaces = Standard.init(&registry);
    try std_ifaces.registerOn(&registry, "/obj");

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &buf, .little);
    const sig = try introspect(&registry, &callMsg("/obj", "", null), &w);
    try testing.expectEqualStrings("s", sig);

    var r = unmarshal.Reader.init(buf.items, .little);
    const xml = try r.string();
    try testing.expect(std.mem.indexOf(u8, xml, "org.freedesktop.DBus.Peer") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "<method name=\"Ping\"") != null);
    try testing.expect(std.mem.indexOf(u8, xml, "org.freedesktop.DBus.Introspectable") != null);
}

var test_version: u32 = 42;

fn versionGetter(ctx: ?*anyopaque, w: *marshal.Writer) HandlerError!void {
    _ = ctx;
    try w.uint32(test_version);
}

const version_props = [_]object.Property{.{ .name = "Version", .sig = "u", .getter = versionGetter }};

test "Properties.GetAll returns the declared properties" {
    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    var std_ifaces = Standard.init(&registry);
    try registry.addInterface("/obj", .{ .name = "t.Thing", .methods = &.{}, .properties = &version_props });
    try std_ifaces.registerOn(&registry, "/obj");

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    var bw = marshal.Writer.init(testing.allocator, &body, .little);
    try bw.string("t.Thing");

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &buf, .little);
    const sig = try propGetAll(&registry, &callMsg("/obj", body.items, "s"), &w);
    try testing.expectEqualStrings("a{sv}", sig);

    var r = unmarshal.Reader.init(buf.items, .little);
    const v = try r.readValue(testing.allocator, "a{sv}");
    defer unmarshal.freeValue(testing.allocator, v);
    try testing.expectEqual(@as(usize, 1), v.array.len);
    try testing.expectEqualStrings("Version", v.array[0].dict_entry[0].string);
    try testing.expectEqual(@as(u32, 42), v.array[0].dict_entry[1].variant.uint32);
}
