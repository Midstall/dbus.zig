//! A D-Bus connection over a Transport: assigns per-connection serials, frames
//! the incoming byte stream into messages, matches method replies to pending
//! callbacks, and routes everything else to filters. Driven asynchronously by the
//! event loop (blocking writes, which suffice for the small control messages in
//! this milestone).

const std = @import("std");
const builtin = @import("builtin");
const el = @import("event_loop.zig");
const message = @import("message.zig");
const Message = message.Message;
const transport = @import("transport.zig");
const Transport = transport.Transport;

const native_endian = builtin.cpu.arch.endian();

pub const Error = message.Error || transport.Error || el.Error;

/// Called when a method reply (return or error) arrives, or with `reply = null`
/// if the connection dropped before a reply came.
pub const ReplyFn = *const fn (ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void;

pub const FilterResult = enum { handled, pass };

/// Called for messages that are not replies to a pending call (signals, incoming
/// method calls). Return `.handled` to stop further filters.
pub const FilterFn = *const fn (ctx: ?*anyopaque, conn: *Connection, msg: *const Message) FilterResult;

const Pending = struct { cb: ReplyFn, ctx: ?*anyopaque };
const Filter = struct { cb: FilterFn, ctx: ?*anyopaque };

// Callback contract (single-threaded event loop):
//   - A reply/filter callback MUST NOT deinit or free the Connection (or an
//     enclosing Bus) it is dispatched on; `processIncoming` dereferences `self`
//     after the callback returns. Defer teardown to after `dispatch` returns.
//   - `sendMessage` performs a blocking write. Two of our own connections driven
//     on one thread can deadlock if both socket buffers fill during a callback.
//     Fine for the small control messages here; revisit with non-blocking writes
//     before the daemon does bulk or broadcast sends.

pub const Connection = struct {
    gpa: std.mem.Allocator,
    transport: Transport,
    loop: *el.EventLoop,
    source: ?*el.Source = null,
    endian: std.builtin.Endian = native_endian,
    serial: u32 = 0,
    in_buf: std.ArrayList(u8) = .empty,
    fds_in: std.ArrayList(i32) = .empty,
    pending: std.AutoHashMapUnmanaged(u32, Pending) = .empty,
    filters: std.ArrayList(Filter) = .empty,
    disconnected: bool = false,

    pub fn init(gpa: std.mem.Allocator, t: Transport, loop: *el.EventLoop) Connection {
        return .{ .gpa = gpa, .transport = t, .loop = loop };
    }

    pub fn deinit(self: *Connection) void {
        if (self.source) |src| {
            self.loop.remove(src);
            self.source = null;
        }
        self.in_buf.deinit(self.gpa);
        for (self.fds_in.items) |fd| _ = linux.close(fd);
        self.fds_in.deinit(self.gpa);
        self.pending.deinit(self.gpa);
        self.filters.deinit(self.gpa);
        self.transport.close();
    }

    /// Start watching the transport fd for readability on the event loop.
    pub fn register(self: *Connection) Error!void {
        self.source = try self.loop.addFd(self.transport.fd, el.READABLE, onEvent, self);
    }

    fn nextSerial(self: *Connection) u32 {
        self.serial +%= 1;
        if (self.serial == 0) self.serial = 1;
        return self.serial;
    }

    fn writeAll(self: *Connection, bytes: []const u8) Error!void {
        var off: usize = 0;
        while (off < bytes.len) {
            const n = try self.transport.write(bytes[off..]);
            if (n == 0) return Error.BrokenPipe;
            off += n;
        }
    }

    /// Serialize and send `msg`, assigning a fresh serial if it has none.
    pub fn sendMessage(self: *Connection, msg: Message) Error!u32 {
        if (self.disconnected) return Error.BrokenPipe;
        var m = msg;
        if (m.serial == 0) m.serial = self.nextSerial();
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(self.gpa);
        try m.serialize(self.gpa, &buf, self.endian);
        try self.writeAll(buf.items);
        return m.serial;
    }

    /// Send a method call and register `cb` to run when its reply arrives.
    pub fn callMethod(self: *Connection, msg: Message, cb: ReplyFn, ctx: ?*anyopaque) Error!u32 {
        if (self.disconnected) return Error.BrokenPipe;
        const serial = self.nextSerial();
        var m = msg;
        m.serial = serial;
        try self.pending.put(self.gpa, serial, .{ .cb = cb, .ctx = ctx });
        errdefer _ = self.pending.remove(serial);
        _ = try self.sendMessage(m);
        return serial;
    }

    pub fn addFilter(self: *Connection, cb: FilterFn, ctx: ?*anyopaque) Error!void {
        try self.filters.append(self.gpa, .{ .cb = cb, .ctx = ctx });
    }

    fn onEvent(mask: u32, data: ?*anyopaque) void {
        const self: *Connection = @ptrCast(@alignCast(data.?));
        if (mask & (el.HANGUP | el.ERROR) != 0) {
            self.fail();
            return;
        }
        if (mask & el.READABLE != 0) self.readReady();
    }

    fn readReady(self: *Connection) void {
        var buf: [8192]u8 = undefined;
        var fdbuf: [transport.max_fds]i32 = undefined;
        const res = self.transport.recvWithFds(&buf, &fdbuf) catch {
            self.fail();
            return;
        };
        if (res.bytes == 0) {
            self.fail(); // EOF
            return;
        }
        self.in_buf.appendSlice(self.gpa, buf[0..res.bytes]) catch {
            self.fail();
            return;
        };
        if (res.fds > 0) {
            self.fds_in.appendSlice(self.gpa, fdbuf[0..res.fds]) catch {
                for (fdbuf[0..res.fds]) |fd| _ = linux.close(fd);
                self.fail();
                return;
            };
        }
        self.processIncoming();
    }

    fn processIncoming(self: *Connection) void {
        while (true) {
            const total = message.wireLength(self.in_buf.items) orelse {
                // Enough bytes to know the length but none returned means a bad
                // endianness byte: a protocol violation.
                if (self.in_buf.items.len >= 16) self.fail();
                return;
            };
            // Reject an absurd declared length before buffering toward it, so a
            // peer cannot make us accumulate gigabytes before deserialize checks.
            if (total > message.max_message_len) {
                self.fail();
                return;
            }
            if (self.in_buf.items.len < total) return; // need more bytes
            var msg = Message.deserialize(self.gpa, self.in_buf.items[0..total]) catch {
                self.fail();
                return;
            };
            // Attach any fds this message declared (they rode in via SCM_RIGHTS,
            // ordered ahead of or with these bytes). Borrowed for the callback;
            // closed right after, so a handler must dup one it wants to keep.
            const nfds = @min(msg.unix_fds orelse 0, self.fds_in.items.len);
            msg.fds = self.fds_in.items[0..nfds];
            self.dispatch(&msg);
            for (self.fds_in.items[0..nfds]) |fd| _ = linux.close(fd);
            const fd_rem = self.fds_in.items.len - nfds;
            std.mem.copyForwards(i32, self.fds_in.items[0..fd_rem], self.fds_in.items[nfds..]);
            self.fds_in.shrinkRetainingCapacity(fd_rem);
            if (self.disconnected) return;
            const rem = self.in_buf.items.len - total;
            std.mem.copyForwards(u8, self.in_buf.items[0..rem], self.in_buf.items[total..]);
            self.in_buf.shrinkRetainingCapacity(rem);
        }
    }

    fn dispatch(self: *Connection, msg: *const Message) void {
        if (msg.msg_type == .method_return or msg.msg_type == .error_) {
            if (msg.reply_serial) |rs| {
                if (self.pending.fetchRemove(rs)) |kv| {
                    kv.value.cb(kv.value.ctx, self, msg);
                    return;
                }
            }
        }
        for (self.filters.items) |f| {
            if (f.cb(f.ctx, self, msg) == .handled) return;
        }
    }

    fn fail(self: *Connection) void {
        if (self.disconnected) return;
        self.disconnected = true;
        var it = self.pending.iterator();
        while (it.next()) |e| e.value_ptr.cb(e.value_ptr.ctx, self, null);
        self.pending.clearRetainingCapacity();
        if (self.source) |src| {
            self.loop.remove(src);
            self.source = null;
        }
    }
};

const testing = std.testing;
const linux = std.os.linux;
const posix = std.posix;

fn socketpair() ![2]i32 {
    var fds: [2]i32 = undefined;
    const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds);
    if (posix.errno(rc) != .SUCCESS) return error.SocketpairFailed;
    return fds;
}

const Echo = struct {
    fn filter(ctx: ?*anyopaque, conn: *Connection, msg: *const Message) FilterResult {
        _ = ctx;
        if (msg.msg_type == .method_call) {
            const reply = Message{ .msg_type = .method_return, .serial = 0, .reply_serial = msg.serial };
            _ = conn.sendMessage(reply) catch {};
            return .handled;
        }
        return .pass;
    }
};

const ReplyCatcher = struct {
    got: bool = false,
    reply_serial: u32 = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *ReplyCatcher = @ptrCast(@alignCast(ctx.?));
        self.got = true;
        if (reply) |r| self.reply_serial = r.reply_serial orelse 0;
    }
};

test "two connections exchange a method call and its reply" {
    var loop = try el.EventLoop.init(testing.allocator);
    defer loop.deinit();

    const fds = try socketpair();
    var client = Connection.init(testing.allocator, Transport.fromFd(fds[0]), &loop);
    defer client.deinit();
    var server = Connection.init(testing.allocator, Transport.fromFd(fds[1]), &loop);
    defer server.deinit();
    try client.register();
    try server.register();
    try server.addFilter(Echo.filter, null);

    var catcher = ReplyCatcher{};
    const call = Message{ .msg_type = .method_call, .serial = 0, .path = "/x", .member = "Do" };
    const serial = try client.callMethod(call, ReplyCatcher.onReply, &catcher);

    var i: usize = 0;
    while (!catcher.got and i < 100) : (i += 1) _ = loop.dispatch(50);
    try testing.expect(catcher.got);
    try testing.expectEqual(serial, catcher.reply_serial);
}

const FdCatcher = struct {
    got: bool = false,
    fd: i32 = -1,
    fn filter(ctx: ?*anyopaque, conn: *Connection, msg: *const Message) FilterResult {
        _ = conn;
        const self: *FdCatcher = @ptrCast(@alignCast(ctx.?));
        if (msg.msg_type != .method_call) return .pass;
        self.got = true;
        if (msg.fds.len == 1) {
            // Borrowed for this callback only; dup to keep it past return.
            const rc = linux.fcntl(msg.fds[0], linux.F.DUPFD_CLOEXEC, 0);
            if (posix.errno(rc) == .SUCCESS) self.fd = @intCast(rc);
        }
        return .handled;
    }
};

const marshal = @import("marshal.zig");

test "a received message exposes its SCM_RIGHTS fds" {
    var loop = try el.EventLoop.init(testing.allocator);
    defer loop.deinit();

    const fds = try socketpair();
    var conn = Connection.init(testing.allocator, Transport.fromFd(fds[0]), &loop);
    defer conn.deinit();
    var peer = Transport.fromFd(fds[1]);
    defer peer.close();
    try conn.register();

    var catcher = FdCatcher{};
    try conn.addFilter(FdCatcher.filter, &catcher);

    // Build a method_call carrying one unix_fd (index 0) in its body.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &body, native_endian);
    try w.unixFd(0);
    const call = Message{
        .msg_type = .method_call,
        .serial = 1,
        .path = "/x",
        .member = "Take",
        .body_signature = "h",
        .unix_fds = 1,
        .body = body.items,
    };
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(testing.allocator);
    try call.serialize(testing.allocator, &wire, native_endian);

    // Pass one end of an auxiliary pipe as the fd.
    const aux = try socketpair();
    var aux_peer = Transport.fromFd(aux[1]);
    defer aux_peer.close();
    _ = try peer.sendWithFds(wire.items, &.{aux[0]});
    _ = linux.close(aux[0]);

    var i: usize = 0;
    while (!catcher.got and i < 50) : (i += 1) _ = loop.dispatch(20);
    try testing.expect(catcher.got);
    try testing.expect(catcher.fd >= 0);

    // Prove the received fd is live: write through aux_peer, read from it.
    defer _ = linux.close(catcher.fd);
    _ = try aux_peer.write("z");
    var rb: [1]u8 = undefined;
    var recv_end = Transport.fromFd(catcher.fd);
    const rn = try recv_end.read(&rb);
    try testing.expectEqual(@as(usize, 1), rn);
    try testing.expectEqualStrings("z", rb[0..]);
}

test "an oversized declared length disconnects instead of buffering" {
    var loop = try el.EventLoop.init(testing.allocator);
    defer loop.deinit();

    const fds = try socketpair();
    var conn = Connection.init(testing.allocator, Transport.fromFd(fds[0]), &loop);
    defer conn.deinit();
    var peer = Transport.fromFd(fds[1]);
    defer peer.close();
    try conn.register();

    // 16-byte header prefix, little-endian, body_len = 0xFFFFFFFF, fields_len = 0.
    const hdr = [16]u8{ 'l', 1, 0, 1, 0xFF, 0xFF, 0xFF, 0xFF, 1, 0, 0, 0, 0, 0, 0, 0 };
    _ = try peer.write(&hdr);

    var i: usize = 0;
    while (!conn.disconnected and i < 20) : (i += 1) _ = loop.dispatch(20);
    try testing.expect(conn.disconnected);
}
