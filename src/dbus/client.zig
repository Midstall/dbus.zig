//! High-level D-Bus client. `Bus.connectUnix` opens a transport, runs EXTERNAL
//! SASL auth (blocking, on the raw socket), then registers the connection with
//! the event loop and performs the org.freedesktop.DBus.Hello handshake to obtain
//! the unique name. After connect, method calls are async via `call`.

const std = @import("std");
const linux = std.os.linux;
const el = @import("event_loop.zig");
const transport = @import("transport.zig");
const Transport = transport.Transport;
const auth = @import("auth.zig");
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const message = @import("message.zig");
const Message = message.Message;
const marshal = @import("marshal.zig");
const unmarshal = @import("unmarshal.zig");
const object = @import("object.zig");
const interfaces = @import("interfaces.zig");
const match = @import("match.zig");

pub const Error = conn_mod.Error || auth.Error || match.Error || error{
    AuthFailed,
    AuthDisconnected,
    HelloFailed,
};

/// Signal handler: invoked for a received signal that matches its rule.
pub const SignalFn = *const fn (ctx: ?*anyopaque, bus: *Bus, signal: *const Message) void;

const SignalHandler = struct {
    rule: match.MatchRule,
    cb: SignalFn,
    ctx: ?*anyopaque,
};

pub const Bus = struct {
    gpa: std.mem.Allocator,
    loop: *el.EventLoop,
    conn: Connection,
    registry: object.Registry,
    std_ifaces: interfaces.Standard = undefined,
    signal_handlers: std.ArrayList(SignalHandler) = .empty,
    unique_name: ?[]u8 = null,
    hello_done: bool = false,
    hello_err: bool = false,

    /// Connect over a unix socket, authenticate as `uid` via EXTERNAL, and Hello.
    /// Returns a heap-allocated Bus (its address is stable, as the connection and
    /// callbacks hold pointers into it). Free with `deinit`.
    pub fn connectUnix(gpa: std.mem.Allocator, loop: *el.EventLoop, path: []const u8, abstract: bool, uid: u32) Error!*Bus {
        var t = try Transport.connectUnix(path, abstract);

        var ac = auth.Client{ .gpa = gpa, .uid = uid, .mechanism = .external };
        defer ac.deinit();
        var leftover: std.ArrayList(u8) = .empty;
        defer leftover.deinit(gpa);
        runExternalAuth(gpa, &t, &ac, &leftover) catch |e| {
            t.close();
            return e;
        };

        const self = gpa.create(Bus) catch |e| {
            t.close();
            return e;
        };
        self.* = .{
            .gpa = gpa,
            .loop = loop,
            .conn = Connection.init(gpa, t, loop),
            .registry = object.Registry.init(gpa),
        };
        self.std_ifaces = interfaces.Standard.init(&self.registry);
        errdefer self.deinit();

        if (leftover.items.len > 0) try self.conn.in_buf.appendSlice(gpa, leftover.items);
        try self.conn.register();
        try self.conn.addFilter(busFilter, self);

        const hello = Message{
            .msg_type = .method_call,
            .serial = 0,
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "Hello",
            .destination = "org.freedesktop.DBus",
        };
        _ = try self.conn.callMethod(hello, onHello, self);

        var i: usize = 0;
        while (!self.hello_done and !self.hello_err and i < 200) : (i += 1) {
            _ = loop.dispatch(50);
        }
        if (!self.hello_done or self.unique_name == null) return Error.HelloFailed;
        return self;
    }

    pub fn deinit(self: *Bus) void {
        self.conn.deinit();
        self.registry.deinit();
        self.signal_handlers.deinit(self.gpa);
        if (self.unique_name) |n| self.gpa.free(n);
        self.gpa.destroy(self);
    }

    /// Issue an async method call; `cb` runs when the reply arrives.
    pub fn call(self: *Bus, msg: Message, cb: conn_mod.ReplyFn, ctx: ?*anyopaque) Error!u32 {
        return self.conn.callMethod(msg, cb, ctx);
    }

    /// Export an object: register `ifaces` at `path` plus the standard interfaces
    /// (Peer/Introspectable/Properties). Call once per path.
    pub fn exportObject(self: *Bus, path: []const u8, ifaces: []const object.Interface) Error!void {
        const is_new = self.registry.interfacesFor(path).len == 0;
        for (ifaces) |iface| try self.registry.addInterface(path, iface);
        if (is_new) try self.std_ifaces.registerOn(&self.registry, path);
    }

    /// Ask the bus to deliver signals matching `rule` and route them to `cb`.
    /// The rule's strings are borrowed and must outlive the Bus.
    pub fn addSignalHandler(self: *Bus, rule: match.MatchRule, cb: SignalFn, ctx: ?*anyopaque) Error!void {
        try self.signal_handlers.append(self.gpa, .{ .rule = rule, .cb = cb, .ctx = ctx });
        errdefer _ = self.signal_handlers.pop();
        const s = try rule.toString(self.gpa);
        defer self.gpa.free(s);
        try self.addMatch(s);
    }

    /// Send org.freedesktop.DBus.AddMatch for a match-rule string (no reply).
    pub fn addMatch(self: *Bus, rule_str: []const u8) Error!void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = marshal.Writer.init(self.gpa, &body, self.conn.endian);
        try w.string(rule_str);
        const msg = Message{
            .msg_type = .method_call,
            .serial = 0,
            .flags = .{ .no_reply_expected = true },
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "AddMatch",
            .destination = "org.freedesktop.DBus",
            .body_signature = "s",
            .body = body.items,
        };
        _ = try self.conn.sendMessage(msg);
    }

    /// Emit a signal message.
    pub fn emitSignal(self: *Bus, signal: Message) Error!u32 {
        return self.conn.sendMessage(signal);
    }

    fn busFilter(ctx: ?*anyopaque, conn: *Connection, msg: *const Message) conn_mod.FilterResult {
        const self: *Bus = @ptrCast(@alignCast(ctx.?));
        switch (msg.msg_type) {
            .method_call => {
                const handled = self.registry.dispatch(conn, msg) catch return .handled;
                return if (handled) .handled else .pass;
            },
            .signal => {
                // The daemon already filtered by the rule's `sender` (resolving a
                // well-known name to the current owner's unique name), so re-check
                // everything EXCEPT sender locally, or well-known-sender rules
                // would drop every signal the daemon correctly delivered.
                // Callbacks must not add/remove signal handlers (the loop holds a
                // slice into signal_handlers).
                for (self.signal_handlers.items) |h| {
                    var local = h.rule;
                    local.sender = null;
                    if (local.matches(msg)) h.cb(h.ctx, self, msg);
                }
                return .pass;
            },
            else => return .pass,
        }
    }

    fn onHello(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *Bus = @ptrCast(@alignCast(ctx.?));
        const r = reply orelse {
            self.hello_err = true;
            return;
        };
        if (r.msg_type != .method_return) {
            self.hello_err = true;
            return;
        }
        var reader = unmarshal.Reader.init(r.body, r.endian);
        const name = reader.string() catch {
            self.hello_err = true;
            return;
        };
        self.unique_name = self.gpa.dupe(u8, name) catch {
            self.hello_err = true;
            return;
        };
        self.hello_done = true;
    }
};

fn writeAllRaw(t: *Transport, bytes: []const u8) Error!void {
    var off: usize = 0;
    while (off < bytes.len) {
        const n = try t.write(bytes[off..]);
        if (n == 0) return Error.AuthDisconnected;
        off += n;
    }
}

/// Drive the EXTERNAL SASL handshake to completion on the raw transport. Any
/// bytes read past the final auth line (the start of the binary stream) are moved
/// into `leftover` for the connection to consume.
fn runExternalAuth(gpa: std.mem.Allocator, t: *Transport, ac: *auth.Client, leftover: *std.ArrayList(u8)) Error!void {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try ac.begin(&out);
    try writeAllRaw(t, out.items);

    var accum: std.ArrayList(u8) = .empty;
    defer accum.deinit(gpa);
    while (true) {
        // Ensure a complete CRLF-terminated line is buffered.
        var idx = std.mem.indexOf(u8, accum.items, "\r\n");
        while (idx == null) {
            var buf: [1024]u8 = undefined;
            const n = try t.read(&buf);
            if (n == 0) return Error.AuthDisconnected;
            try accum.appendSlice(gpa, buf[0..n]);
            idx = std.mem.indexOf(u8, accum.items, "\r\n");
        }
        const line = accum.items[0..idx.?];
        out.clearRetainingCapacity();
        const st = try ac.feedLine(line, &out);
        const consumed = idx.? + 2;
        const rem = accum.items.len - consumed;
        std.mem.copyForwards(u8, accum.items[0..rem], accum.items[consumed..]);
        accum.shrinkRetainingCapacity(rem);

        if (out.items.len > 0) try writeAllRaw(t, out.items);
        switch (st) {
            .authenticated => {
                try leftover.appendSlice(gpa, accum.items);
                return;
            },
            .need_more => continue,
            .rejected, .failed => return Error.AuthFailed,
        }
    }
}

const testing = std.testing;

const ListCatcher = struct {
    gpa: std.mem.Allocator,
    done: bool = false,
    found: bool = false,

    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *ListCatcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        if (r.msg_type != .method_return) return;
        var reader = unmarshal.Reader.init(r.body, r.endian);
        const v = reader.readValue(self.gpa, "as") catch return;
        defer unmarshal.freeValue(self.gpa, v);
        for (v.array) |item| {
            if (std.mem.eql(u8, item.string, "org.freedesktop.DBus")) self.found = true;
        }
    }
};

test "connect to the running session bus, Hello and ListNames (interop)" {
    // Uses the real session dbus-daemon if reachable; otherwise skips.
    const uid = linux.getuid();
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/run/user/{d}/bus", .{uid});

    var loop = try el.EventLoop.init(testing.allocator);
    defer loop.deinit();

    const bus = Bus.connectUnix(testing.allocator, &loop, path, false, uid) catch {
        return error.SkipZigTest;
    };
    defer bus.deinit();

    const name = bus.unique_name.?;
    // A unique name looks like ":1.42".
    try testing.expect(name.len >= 3);
    try testing.expectEqual(@as(u8, ':'), name[0]);
    try testing.expect(std.mem.indexOfScalar(u8, name, '.') != null);

    // A second round-trip: ListNames must include the bus driver itself.
    var lc = ListCatcher{ .gpa = testing.allocator };
    const list_msg = Message{
        .msg_type = .method_call,
        .serial = 0,
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "ListNames",
        .destination = "org.freedesktop.DBus",
    };
    _ = try bus.call(list_msg, ListCatcher.onReply, &lc);
    var j: usize = 0;
    while (!lc.done and j < 200) : (j += 1) _ = loop.dispatch(50);
    try testing.expect(lc.found);
}

const PongCatcher = struct {
    done: bool = false,
    is_return: bool = false,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *PongCatcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        self.is_return = r.msg_type == .method_return;
    }
};

const IntrospectCatcher = struct {
    gpa: std.mem.Allocator,
    done: bool = false,
    has_peer: bool = false,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *IntrospectCatcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        if (r.msg_type != .method_return) return;
        var rd = unmarshal.Reader.init(r.body, r.endian);
        const xml = rd.string() catch return;
        self.has_peer = std.mem.indexOf(u8, xml, "org.freedesktop.DBus.Peer") != null;
    }
};

test "export an object and call it via the bus routing back to us (interop)" {
    const uid = linux.getuid();
    var path_buf: [64]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/run/user/{d}/bus", .{uid});

    var loop = try el.EventLoop.init(testing.allocator);
    defer loop.deinit();

    const bus = Bus.connectUnix(testing.allocator, &loop, path, false, uid) catch {
        return error.SkipZigTest;
    };
    defer bus.deinit();

    // Export the standard interfaces at "/" (no custom interfaces).
    try bus.exportObject("/", &.{});

    // Call Peer.Ping on our OWN unique name: the daemon routes it back to us, our
    // dispatcher answers, and the reply routes back. Full loop through the daemon.
    var pc = PongCatcher{};
    const ping = Message{
        .msg_type = .method_call,
        .serial = 0,
        .path = "/",
        .interface = "org.freedesktop.DBus.Peer",
        .member = "Ping",
        .destination = bus.unique_name.?,
    };
    _ = try bus.call(ping, PongCatcher.onReply, &pc);
    var i: usize = 0;
    while (!pc.done and i < 200) : (i += 1) _ = loop.dispatch(50);
    try testing.expect(pc.done);
    try testing.expect(pc.is_return);

    // Introspect ourselves and confirm the Peer interface shows up.
    var ic = IntrospectCatcher{ .gpa = testing.allocator };
    const intro = Message{
        .msg_type = .method_call,
        .serial = 0,
        .path = "/",
        .interface = "org.freedesktop.DBus.Introspectable",
        .member = "Introspect",
        .destination = bus.unique_name.?,
    };
    _ = try bus.call(intro, IntrospectCatcher.onReply, &ic);
    var k: usize = 0;
    while (!ic.done and k < 200) : (k += 1) _ = loop.dispatch(50);
    try testing.expect(ic.done);
    try testing.expect(ic.has_peer);
}
