//! Exported object registry: maps object paths to interfaces with typed method
//! handlers, and dispatches an incoming method_call to the matching handler,
//! sending the reply (or an error) back to the caller.

const std = @import("std");
const message = @import("message.zig");
const Message = message.Message;
const marshal = @import("marshal.zig");
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;

pub const HandlerError = error{Failed} || marshal.Writer.Error;

/// A method handler marshals its reply body into `w` and returns the reply body
/// signature ("" for no return values). Returning an error makes the dispatcher
/// send an org.freedesktop.DBus.Error.Failed reply.
pub const MethodFn = *const fn (ctx: ?*anyopaque, call: *const Message, w: *marshal.Writer) HandlerError![]const u8;

pub const Method = struct {
    name: []const u8,
    handler: MethodFn,
    ctx: ?*anyopaque = null,
    /// Argument signatures for introspection (empty = unknown/none).
    in_sig: []const u8 = "",
    out_sig: []const u8 = "",
};

/// A readable property: `getter` marshals the value (of type `sig`) into `w`.
pub const PropertyFn = *const fn (ctx: ?*anyopaque, w: *marshal.Writer) HandlerError!void;

pub const Property = struct {
    name: []const u8,
    sig: []const u8,
    getter: PropertyFn,
    ctx: ?*anyopaque = null,
};

pub const Interface = struct {
    name: []const u8,
    methods: []const Method,
    properties: []const Property = &.{},
};

pub const Error = conn_mod.Error;

pub const Registry = struct {
    gpa: std.mem.Allocator,
    objects: std.ArrayList(Entry),

    const Entry = struct {
        path: []const u8,
        interfaces: std.ArrayList(Interface),
    };

    pub fn init(gpa: std.mem.Allocator) Registry {
        return .{ .gpa = gpa, .objects = .empty };
    }

    pub fn deinit(self: *Registry) void {
        for (self.objects.items) |*e| e.interfaces.deinit(self.gpa);
        self.objects.deinit(self.gpa);
    }

    fn find(self: *Registry, path: []const u8) ?*Entry {
        for (self.objects.items) |*e| {
            if (std.mem.eql(u8, e.path, path)) return e;
        }
        return null;
    }

    /// Register `iface` on `path`, creating the object entry if needed. Interface
    /// data (names, method slices) is borrowed and must outlive the registry.
    pub fn addInterface(self: *Registry, path: []const u8, iface: Interface) Error!void {
        if (self.find(path)) |e| {
            try e.interfaces.append(self.gpa, iface);
            return;
        }
        var ifaces: std.ArrayList(Interface) = .empty;
        errdefer ifaces.deinit(self.gpa);
        try ifaces.append(self.gpa, iface);
        try self.objects.append(self.gpa, .{ .path = path, .interfaces = ifaces });
    }

    /// Iterate the interfaces registered on `path` (for Introspect).
    pub fn interfacesFor(self: *Registry, path: []const u8) []const Interface {
        if (self.find(path)) |e| return e.interfaces.items;
        return &.{};
    }

    fn findMethod(entry: *Entry, iface: ?[]const u8, member: []const u8) ?Method {
        for (entry.interfaces.items) |def| {
            if (iface) |want| if (!std.mem.eql(u8, def.name, want)) continue;
            for (def.methods) |m| if (std.mem.eql(u8, m.name, member)) return m;
        }
        return null;
    }

    /// Dispatch a method_call to a registered handler. Returns true if the object
    /// path was found (even if the member was not, in which case an error reply is
    /// sent); false if no object is registered at that path.
    pub fn dispatch(self: *Registry, conn: *Connection, call: *const Message) Error!bool {
        const path = call.path orelse return false;
        const entry = self.find(path) orelse {
            // We are the destination, so answer an unknown path rather than
            // dropping the call (the caller would otherwise hang until timeout).
            try self.sendError(conn, call, "org.freedesktop.DBus.Error.UnknownObject", "No such object");
            return true;
        };
        const member = call.member orelse return false;

        const method = findMethod(entry, call.interface, member) orelse {
            try self.sendError(conn, call, "org.freedesktop.DBus.Error.UnknownMethod", "Unknown method");
            return true;
        };

        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = marshal.Writer.init(self.gpa, &body, conn.endian);
        const sig = method.handler(method.ctx, call, &w) catch {
            try self.sendError(conn, call, "org.freedesktop.DBus.Error.Failed", "Handler failed");
            return true;
        };

        // A handler whose returned signature and body disagree would put a
        // malformed message on the wire; the daemon would reject it.
        if ((sig.len == 0) != (body.items.len == 0)) {
            try self.sendError(conn, call, "org.freedesktop.DBus.Error.Failed", "Handler produced inconsistent reply");
            return true;
        }

        if (!call.flags.no_reply_expected) {
            const reply = Message{
                .msg_type = .method_return,
                .serial = 0,
                .reply_serial = call.serial,
                .destination = call.sender,
                .body_signature = if (sig.len > 0) sig else null,
                .body = body.items,
            };
            _ = try conn.sendMessage(reply);
        }
        return true;
    }

    fn sendError(self: *Registry, conn: *Connection, call: *const Message, name: []const u8, text: []const u8) Error!void {
        if (call.flags.no_reply_expected) return;
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = marshal.Writer.init(self.gpa, &body, conn.endian);
        try w.string(text);
        const err = Message{
            .msg_type = .error_,
            .serial = 0,
            .reply_serial = call.serial,
            .error_name = name,
            .destination = call.sender,
            .body_signature = "s",
            .body = body.items,
        };
        _ = try conn.sendMessage(err);
    }
};

const testing = std.testing;
const linux = std.os.linux;
const posix = std.posix;
const el = @import("event_loop.zig");
const Transport = @import("transport.zig").Transport;
const unmarshal = @import("unmarshal.zig");

fn echoHandler(ctx: ?*anyopaque, call: *const Message, w: *marshal.Writer) HandlerError![]const u8 {
    _ = ctx;
    var r = unmarshal.Reader.init(call.body, call.endian);
    const v = r.int32() catch return error.Failed;
    try w.int32(v);
    return "i";
}

const echo_methods = [_]Method{.{ .name = "Echo", .handler = echoHandler }};

const RegistryFilter = struct {
    registry: *Registry,
    fn filter(ctx: ?*anyopaque, conn: *Connection, msg: *const Message) conn_mod.FilterResult {
        const self: *RegistryFilter = @ptrCast(@alignCast(ctx.?));
        if (msg.msg_type == .method_call) {
            _ = self.registry.dispatch(conn, msg) catch {};
            return .handled;
        }
        return .pass;
    }
};

const IntCatcher = struct {
    got: bool = false,
    value: i32 = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *IntCatcher = @ptrCast(@alignCast(ctx.?));
        self.got = true;
        const r = reply orelse return;
        if (r.msg_type != .method_return) return;
        var rd = unmarshal.Reader.init(r.body, r.endian);
        self.value = rd.int32() catch 0;
    }
};

fn socketpair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    if (posix.errno(rc) != .SUCCESS) return error.SocketpairFailed;
    return fds;
}

test "dispatch routes a method call to a handler and replies" {
    var loop = try el.EventLoop.init(testing.allocator);
    defer loop.deinit();

    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.addInterface("/test", .{ .name = "t.Echo", .methods = &echo_methods });

    const fds = try socketpair();
    var client = Connection.init(testing.allocator, Transport.fromFd(fds[0]), &loop);
    defer client.deinit();
    var server = Connection.init(testing.allocator, Transport.fromFd(fds[1]), &loop);
    defer server.deinit();
    try client.register();
    try server.register();
    var rf = RegistryFilter{ .registry = &registry };
    try server.addFilter(RegistryFilter.filter, &rf);

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &body, client.endian);
    try w.int32(7);

    var catcher = IntCatcher{};
    const call = Message{
        .msg_type = .method_call,
        .serial = 0,
        .path = "/test",
        .interface = "t.Echo",
        .member = "Echo",
        .body_signature = "i",
        .body = body.items,
    };
    _ = try client.callMethod(call, IntCatcher.onReply, &catcher);

    var i: usize = 0;
    while (!catcher.got and i < 100) : (i += 1) _ = loop.dispatch(50);
    try testing.expect(catcher.got);
    try testing.expectEqual(@as(i32, 7), catcher.value);
}

const ErrCatcher = struct {
    got: bool = false,
    is_error: bool = false,
    name_buf: [96]u8 = undefined,
    name_len: usize = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *ErrCatcher = @ptrCast(@alignCast(ctx.?));
        self.got = true;
        const r = reply orelse return;
        if (r.msg_type != .error_) return;
        self.is_error = true;
        if (r.error_name) |nm| {
            const n = @min(nm.len, self.name_buf.len);
            @memcpy(self.name_buf[0..n], nm[0..n]);
            self.name_len = n;
        }
    }
};

test "dispatch answers an unknown object path with UnknownObject" {
    var loop = try el.EventLoop.init(testing.allocator);
    defer loop.deinit();

    var registry = Registry.init(testing.allocator);
    defer registry.deinit();
    try registry.addInterface("/test", .{ .name = "t.Echo", .methods = &echo_methods });

    const fds = try socketpair();
    var client = Connection.init(testing.allocator, Transport.fromFd(fds[0]), &loop);
    defer client.deinit();
    var server = Connection.init(testing.allocator, Transport.fromFd(fds[1]), &loop);
    defer server.deinit();
    try client.register();
    try server.register();
    var rf = RegistryFilter{ .registry = &registry };
    try server.addFilter(RegistryFilter.filter, &rf);

    var ec = ErrCatcher{};
    const call = Message{ .msg_type = .method_call, .serial = 0, .path = "/nope", .member = "X" };
    _ = try client.callMethod(call, ErrCatcher.onReply, &ec);

    var i: usize = 0;
    while (!ec.got and i < 100) : (i += 1) _ = loop.dispatch(50);
    try testing.expect(ec.is_error);
    try testing.expectEqualStrings("org.freedesktop.DBus.Error.UnknownObject", ec.name_buf[0..ec.name_len]);
}
