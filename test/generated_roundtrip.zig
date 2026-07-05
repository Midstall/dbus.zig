//! End-to-end test of the generated bindings: a generated server Vtable and a
//! generated client Proxy exchange typed method calls through our own daemon.

const std = @import("std");
const dbus = @import("dbus");
const calc = @import("calc");
const linux = std.os.linux;
const Daemon = dbus.daemon.bus.Daemon;
const Bus = dbus.client.Bus;
const EventLoop = dbus.event_loop.EventLoop;
const Message = dbus.message.Message;
const Connection = dbus.connection.Connection;
const testing = std.testing;

const Calc = calc.org_example_Calc;

const CalcImpl = struct {
    buf: [128]u8 = undefined,
    pub fn Add(self: *CalcImpl, a: i32, b: i32) i32 {
        _ = self;
        return a + b;
    }
    pub fn Concat(self: *CalcImpl, x: []const u8, y: []const u8) []const u8 {
        const n = std.fmt.bufPrint(&self.buf, "{s}{s}", .{ x, y }) catch return "";
        return n;
    }
};

const AddCatcher = struct {
    done: bool = false,
    sum: i32 = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *AddCatcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        if (r.msg_type != .method_return) return;
        const decoded = Calc.Proxy.decodeAdd(r) catch return;
        self.sum = decoded.value;
    }
};

const ConcatCatcher = struct {
    done: bool = false,
    buf: [64]u8 = undefined,
    len: usize = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *ConcatCatcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        if (r.msg_type != .method_return) return;
        const decoded = Calc.Proxy.decodeConcat(r) catch return;
        const m = @min(decoded.value.len, self.buf.len);
        @memcpy(self.buf[0..m], decoded.value[0..m]);
        self.len = m;
    }
};

fn daemonThread(d: *Daemon) void {
    d.run();
}

fn drive(loop: *EventLoop, flag: *const bool) void {
    var i: usize = 0;
    while (!flag.* and i < 300) : (i += 1) _ = loop.dispatch(20);
}

/// Connect with a few retries: under parallel test binaries the daemon thread
/// can be starved long enough for the one-shot Hello to time out (the known
/// blocking-auth limitation). Retrying makes this generated-code test reliable.
fn connectRetry(gpa: std.mem.Allocator, loop: *EventLoop, sock: []const u8, uid: u32) !*Bus {
    var attempt: usize = 0;
    while (attempt < 20) : (attempt += 1) {
        if (Bus.connectUnix(gpa, loop, sock, true, uid)) |bus| {
            return bus;
        } else |_| {}
    }
    return error.ConnectFailed;
}

test "generated proxy and vtable round-trip through our daemon" {
    var dgpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = dgpa_state.deinit();
    const dgpa = dgpa_state.allocator();

    var dloop = try EventLoop.init(dgpa);
    defer dloop.deinit();
    const d = try Daemon.init(dgpa, &dloop);
    defer d.deinit();

    var name_buf: [64]u8 = undefined;
    const sock = try std.fmt.bufPrint(&name_buf, "dbuszig-gen-{d}", .{linux.getpid()});
    try d.listenUnix(sock, true);
    const thread = try std.Thread.spawn(.{}, daemonThread, .{d});
    defer {
        d.stop();
        thread.join();
    }

    var cloop = try EventLoop.init(testing.allocator);
    defer cloop.deinit();
    const uid = linux.getuid();
    const a = try connectRetry(testing.allocator, &cloop, sock, uid);
    defer a.deinit();
    const b = try connectRetry(testing.allocator, &cloop, sock, uid);
    defer b.deinit();

    // A exports the generated Calc vtable and claims the well-known name.
    var impl = CalcImpl{};
    var vt = Calc.Vtable(CalcImpl).init(&impl);
    try a.exportObject("/calc", &.{vt.interface()});
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(testing.allocator);
        var w = dbus.marshal.Writer.init(testing.allocator, &body, a.conn.endian);
        try w.string("org.example.Calc");
        try w.uint32(0);
        var done = false;
        const H = struct {
            fn cb(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
                _ = conn;
                _ = reply;
                const f: *bool = @ptrCast(@alignCast(ctx.?));
                f.* = true;
            }
        };
        _ = try a.call(.{ .msg_type = .method_call, .serial = 0, .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "RequestName", .destination = "org.freedesktop.DBus", .body_signature = "su", .body = body.items }, H.cb, &done);
        drive(&cloop, &done);
    }

    // B calls Add(2, 3) via the generated proxy; expect 5.
    var proxy = Calc.Proxy{ .bus = b, .destination = "org.example.Calc", .path = "/calc" };
    var ac = AddCatcher{};
    _ = try proxy.Add(2, 3, AddCatcher.onReply, &ac);
    drive(&cloop, &ac.done);
    try testing.expect(ac.done);
    try testing.expectEqual(@as(i32, 5), ac.sum);

    // B calls Concat("foo", "bar") via the generated proxy; expect "foobar".
    var cc = ConcatCatcher{};
    _ = try proxy.Concat("foo", "bar", ConcatCatcher.onReply, &cc);
    drive(&cloop, &cc.done);
    try testing.expect(cc.done);
    try testing.expectEqualStrings("foobar", cc.buf[0..cc.len]);
}
