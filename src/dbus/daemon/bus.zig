//! The message-bus daemon core: listen on a unix socket, authenticate each
//! accepted client (server EXTERNAL), assign it a unique name, and route its
//! messages. The org.freedesktop.DBus driver methods live in driver.zig; this
//! file owns the listen/accept/auth/route lifecycle and the client table.
//!
//! Server auth runs blocking in the accept handler (fine for prompt clients and
//! tests; a production daemon would make it async). Drive with `run`/`stop`;
//! `run` may live on its own thread while clients connect from another.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const posix = std.posix;

const native_endian = builtin.cpu.arch.endian();
const el = @import("../event_loop.zig");
const transport = @import("../transport.zig");
const Transport = transport.Transport;
const auth = @import("../auth.zig");
const conn_mod = @import("../connection.zig");
const Connection = conn_mod.Connection;
const message = @import("../message.zig");
const Message = message.Message;
const marshal = @import("../marshal.zig");
const match = @import("../match.zig");
const names = @import("names.zig");
const NameRegistry = names.NameRegistry;
const ConnId = names.ConnId;
const driver = @import("driver.zig");
const config_mod = @import("config.zig");
const policy_mod = @import("policy.zig");
const activation = @import("activation.zig");

pub const Error = error{
    ListenFailed,
    AuthFailed,
} || conn_mod.Error;

pub const Ucred = extern struct { pid: i32, uid: u32, gid: u32 };

fn peerCred(fd: i32) ?Ucred {
    var cred: Ucred = undefined;
    var len: linux.socklen_t = @sizeOf(Ucred);
    const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.PEERCRED, @ptrCast(&cred), &len);
    if (posix.errno(rc) != .SUCCESS) return null;
    return cred;
}

pub const Client = struct {
    id: ConnId,
    daemon: *Daemon,
    conn: Connection,
    unique_name: []u8,
    uid: u32,
    pid: i32,
    matches: std.ArrayList(match.MatchRule) = .empty,
};

pub const Daemon = struct {
    gpa: std.mem.Allocator,
    loop: *el.EventLoop,
    guid: [32]u8,
    listen_fd: i32 = -1,
    listen_source: ?*el.Source = null,
    registry: NameRegistry,
    clients: std.AutoHashMapUnmanaged(ConnId, *Client) = .empty,
    unique_map: std.StringHashMapUnmanaged(ConnId) = .empty,
    next_id: ConnId = 0,
    running: bool = true,
    config: ?config_mod.Config = null,
    policy: policy_mod.PolicySet = .{},
    services: activation.ServiceRegistry,

    pub fn init(gpa: std.mem.Allocator, loop: *el.EventLoop) !*Daemon {
        const self = try gpa.create(Daemon);
        self.* = .{ .gpa = gpa, .loop = loop, .guid = undefined, .registry = NameRegistry.init(gpa), .services = activation.ServiceRegistry.init(gpa) };
        auth.genGuid(&self.guid);
        return self;
    }

    /// Register a `.service` file body for activation.
    pub fn addServiceFile(self: *Daemon, body: []const u8) !void {
        try self.services.add(body);
    }

    /// Adopt a parsed config; policy is then enforced on send and name ownership.
    pub fn loadConfig(self: *Daemon, cfg: config_mod.Config) void {
        self.config = cfg;
        self.policy = .{ .config = &self.config.? };
    }

    /// Whether `client` may own `name` under the current policy.
    pub fn mayOwn(self: *Daemon, client: *Client, name: []const u8) bool {
        return self.policy.canOwn(client.uid, name);
    }

    pub fn deinit(self: *Daemon) void {
        self.services.deinit();
        if (self.config) |*c| c.deinit();
        if (self.listen_source) |src| self.loop.remove(src);
        if (self.listen_fd >= 0) _ = linux.close(self.listen_fd);
        var it = self.clients.valueIterator();
        while (it.next()) |cptr| self.destroyClient(cptr.*);
        self.clients.deinit(self.gpa);
        self.unique_map.deinit(self.gpa);
        self.registry.deinit();
        self.gpa.destroy(self);
    }

    /// Bind + listen on a unix socket (abstract or filesystem path) and watch it.
    pub fn listenUnix(self: *Daemon, path: []const u8, abstract: bool) Error!void {
        const s = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        if (posix.errno(s) != .SUCCESS) return Error.ListenFailed;
        const fd: i32 = @intCast(s);
        errdefer _ = linux.close(fd);

        var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = undefined };
        const off = @offsetOf(linux.sockaddr.un, "path");
        var namelen: usize = off;
        if (abstract) {
            addr.path[0] = 0;
            @memcpy(addr.path[1 .. 1 + path.len], path);
            namelen += 1 + path.len;
        } else {
            @memcpy(addr.path[0..path.len], path);
            addr.path[path.len] = 0;
            namelen += path.len + 1;
        }
        if (posix.errno(linux.bind(fd, @ptrCast(&addr), @intCast(namelen))) != .SUCCESS) return Error.ListenFailed;
        if (posix.errno(linux.listen(fd, 16)) != .SUCCESS) return Error.ListenFailed;

        self.listen_fd = fd;
        self.listen_source = try self.loop.addFd(fd, el.READABLE, onAccept, self);
    }

    pub fn run(self: *Daemon) void {
        while (self.running) {
            _ = self.loop.dispatch(100);
            self.reapDisconnected();
        }
    }

    pub fn stop(self: *Daemon) void {
        self.running = false;
    }

    /// Remove clients whose connection dropped, releasing their names and
    /// emitting the resulting NameOwnerChanged signals. Runs outside dispatch.
    fn reapDisconnected(self: *Daemon) void {
        var dead: std.ArrayList(ConnId) = .empty;
        defer dead.deinit(self.gpa);
        var it = self.clients.valueIterator();
        while (it.next()) |cptr| {
            if (cptr.*.conn.disconnected) dead.append(self.gpa, cptr.*.id) catch {};
        }
        for (dead.items) |id| self.dropClient(id);
    }

    fn dropClient(self: *Daemon, id: ConnId) void {
        const client = self.clients.get(id) orelse return;

        // Give up any well-known names, announcing the ownership changes.
        var changes: std.ArrayList(names.OwnerChange) = .empty;
        defer changes.deinit(self.gpa);
        defer for (changes.items) |ch| self.gpa.free(ch.name);
        self.registry.releaseAll(id, &changes) catch {};
        for (changes.items) |ch| {
            const new_name = if (ch.new_owner) |n| (if (self.clients.get(n)) |c| c.unique_name else "") else "";
            self.emitNameOwnerChanged(ch.name, client.unique_name, new_name);
        }
        // The unique name itself disappears.
        self.emitNameOwnerChanged(client.unique_name, client.unique_name, "");

        _ = self.unique_map.remove(client.unique_name);
        _ = self.clients.remove(id);
        self.destroyClient(client);
    }

    fn onAccept(mask: u32, data: ?*anyopaque) void {
        _ = mask;
        const self: *Daemon = @ptrCast(@alignCast(data.?));
        const rc = linux.accept4(self.listen_fd, null, null, linux.SOCK.CLOEXEC);
        if (posix.errno(rc) != .SUCCESS) return;
        const fd: i32 = @intCast(rc);

        const cred = peerCred(fd) orelse {
            _ = linux.close(fd);
            return;
        };

        var leftover: std.ArrayList(u8) = .empty;
        defer leftover.deinit(self.gpa);
        var server = auth.Server.init(self.gpa, cred.uid);
        runServerAuth(self.gpa, fd, &server, &leftover) catch {
            _ = linux.close(fd);
            return;
        };

        // addClient takes ownership of fd and closes it on any error path.
        self.addClient(fd, cred.uid, cred.pid, leftover.items) catch {};
    }

    fn addClient(self: *Daemon, fd: i32, uid: u32, pid: i32, leftover: []const u8) !void {
        // Before the Connection owns the fd, close it explicitly on failure.
        const client = self.gpa.create(Client) catch |e| {
            _ = linux.close(fd);
            return e;
        };
        errdefer self.gpa.destroy(client);
        const unique = self.registry.nextUnique() catch |e| {
            _ = linux.close(fd);
            return e;
        };
        errdefer self.gpa.free(unique);

        const id = self.next_id;
        self.next_id += 1;
        client.* = .{
            .id = id,
            .daemon = self,
            .conn = Connection.init(self.gpa, Transport.fromFd(fd), self.loop),
            .unique_name = unique,
            .uid = uid,
            .pid = pid,
        };
        // From here the Connection owns fd; deinit closes it and removes the source.
        errdefer client.conn.deinit();

        if (leftover.len > 0) try client.conn.in_buf.appendSlice(self.gpa, leftover);
        try self.clients.put(self.gpa, id, client);
        errdefer _ = self.clients.remove(id);
        try self.unique_map.put(self.gpa, unique, id);
        errdefer _ = self.unique_map.remove(unique);

        try client.conn.register();
        try client.conn.addFilter(clientFilter, client);
    }

    fn destroyClient(self: *Daemon, client: *Client) void {
        client.conn.deinit();
        for (client.matches.items) |*r| r.deinitOwned(self.gpa);
        client.matches.deinit(self.gpa);
        self.gpa.free(client.unique_name);
        self.gpa.destroy(client);
    }

    /// Resolve a destination name (unique `:1.N` or well-known) to a client.
    pub fn resolve(self: *Daemon, name: []const u8) ?*Client {
        const id = if (name.len > 0 and name[0] == ':')
            self.unique_map.get(name) orelse return null
        else
            self.registry.owner(name) orelse return null;
        return self.clients.get(id);
    }

    fn clientFilter(ctx: ?*anyopaque, conn: *Connection, msg: *const Message) conn_mod.FilterResult {
        const client: *Client = @ptrCast(@alignCast(ctx.?));
        client.daemon.handleMessage(client, conn, msg);
        return .handled;
    }

    fn handleMessage(self: *Daemon, client: *Client, conn: *Connection, msg: *const Message) void {
        // Messages addressed to the bus driver.
        const to_driver = if (msg.destination) |d| std.mem.eql(u8, d, "org.freedesktop.DBus") else false;
        if (to_driver) {
            _ = conn;
            driver.handle(self, client, msg) catch {};
            return;
        }
        // Signals with no destination broadcast to matching clients.
        if (msg.msg_type == .signal and msg.destination == null) {
            self.broadcast(client, msg);
            return;
        }
        // Otherwise route to the destination.
        if (msg.destination) |dest| {
            self.routeTo(client, dest, msg);
        }
    }

    /// Forward `msg` from `from` to the client owning `dest`, stamping SENDER.
    pub fn routeTo(self: *Daemon, from: *Client, dest: []const u8, msg: *const Message) void {
        // Policy gates outgoing method calls; replies and errors are exempt (a
        // deny rule must not block a legitimate reply routed back to the caller).
        if (msg.msg_type == .method_call and !self.policy.canSend(from.uid, dest, msg.interface, msg.member)) {
            self.replyError(from, msg, "org.freedesktop.DBus.Error.AccessDenied", "Rejected by policy");
            return;
        }
        const target = self.resolve(dest) orelse {
            self.replyError(from, msg, "org.freedesktop.DBus.Error.NameHasNoOwner", "No such destination");
            return;
        };
        var m = msg.*;
        // Preserve the original sender's serial so the reply's reply_serial still
        // matches the caller's pending call; stamp the authenticated sender.
        m.sender = from.unique_name;
        _ = target.conn.sendMessage(m) catch {};
    }

    /// Broadcast a signal to every client (except the sender) whose match rules
    /// select it, stamping SENDER.
    pub fn broadcast(self: *Daemon, from: *Client, msg: *const Message) void {
        var m = msg.*;
        m.sender = from.unique_name;
        var it = self.clients.valueIterator();
        while (it.next()) |cptr| {
            const c = cptr.*;
            if (c.id == from.id) continue;
            for (c.matches.items) |rule| {
                var local = rule;
                local.sender = null;
                if (local.matches(&m)) {
                    var send_m = m;
                    send_m.serial = 0;
                    _ = c.conn.sendMessage(send_m) catch {};
                    break;
                }
            }
        }
    }

    pub fn replyError(self: *Daemon, to: *Client, call: *const Message, name: []const u8, text: []const u8) void {
        if (call.flags.no_reply_expected) return;
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = marshal.Writer.init(self.gpa, &body, to.conn.endian);
        w.string(text) catch return;
        const err = Message{
            .msg_type = .error_,
            .serial = 0,
            .reply_serial = call.serial,
            .error_name = name,
            .sender = "org.freedesktop.DBus",
            .destination = to.unique_name,
            .body_signature = "s",
            .body = body.items,
        };
        _ = to.conn.sendMessage(err) catch {};
    }

    /// Broadcast org.freedesktop.DBus.NameOwnerChanged(name, old, new) to every
    /// client whose match rules select it.
    pub fn emitNameOwnerChanged(self: *Daemon, name: []const u8, old: []const u8, new: []const u8) void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = marshal.Writer.init(self.gpa, &body, native_endian);
        w.string(name) catch return;
        w.string(old) catch return;
        w.string(new) catch return;
        const sig = Message{
            .msg_type = .signal,
            .serial = 0,
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = "NameOwnerChanged",
            .sender = "org.freedesktop.DBus",
            .body_signature = "sss",
            .body = body.items,
            .endian = native_endian,
        };
        self.broadcastSignal(&sig);
    }

    fn broadcastSignal(self: *Daemon, sig: *const Message) void {
        var it = self.clients.valueIterator();
        while (it.next()) |cptr| {
            const c = cptr.*;
            for (c.matches.items) |rule| {
                var local = rule;
                local.sender = null;
                if (local.matches(sig)) {
                    var m = sig.*;
                    m.serial = 0;
                    _ = c.conn.sendMessage(m) catch {};
                    break;
                }
            }
        }
    }

    /// Send a directed NameAcquired/NameLost signal (member) carrying `name`.
    pub fn sendDirectedSignal(self: *Daemon, client: *Client, member: []const u8, name: []const u8) void {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(self.gpa);
        var w = marshal.Writer.init(self.gpa, &body, client.conn.endian);
        w.string(name) catch return;
        const sig = Message{
            .msg_type = .signal,
            .serial = 0,
            .path = "/org/freedesktop/DBus",
            .interface = "org.freedesktop.DBus",
            .member = member,
            .sender = "org.freedesktop.DBus",
            .destination = client.unique_name,
            .body_signature = "s",
            .body = body.items,
        };
        _ = client.conn.sendMessage(sig) catch {};
    }
};

fn writeAllFd(fd: i32, bytes: []const u8) !void {
    var off: usize = 0;
    while (off < bytes.len) {
        const rc = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (posix.errno(rc) != .SUCCESS) return error.WriteFailed;
        const n: usize = @intCast(rc);
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}

/// Drive the server SASL handshake to completion on a fresh (blocking) fd.
/// Bytes past the final auth line go into `leftover` for the connection.
fn runServerAuth(gpa: std.mem.Allocator, fd: i32, server: *auth.Server, leftover: *std.ArrayList(u8)) !void {
    // The client sends a leading NUL before any AUTH line.
    var nul: [1]u8 = undefined;
    const rn = try posix.read(fd, &nul);
    if (rn == 0) return error.AuthFailed;

    var accum: std.ArrayList(u8) = .empty;
    defer accum.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);

    while (true) {
        var idx = std.mem.indexOf(u8, accum.items, "\r\n");
        while (idx == null) {
            // Cap the auth buffer so a client streaming bytes without a line
            // terminator cannot drive the daemon to OOM.
            if (accum.items.len > 64 * 1024) return error.AuthFailed;
            var buf: [1024]u8 = undefined;
            const n = try posix.read(fd, &buf);
            if (n == 0) return error.AuthFailed;
            try accum.appendSlice(gpa, buf[0..n]);
            idx = std.mem.indexOf(u8, accum.items, "\r\n");
        }
        const line = accum.items[0..idx.?];
        out.clearRetainingCapacity();
        const st = try server.feedLine(line, &out);
        const consumed = idx.? + 2;
        const rem = accum.items.len - consumed;
        std.mem.copyForwards(u8, accum.items[0..rem], accum.items[consumed..]);
        accum.shrinkRetainingCapacity(rem);

        if (out.items.len > 0) try writeAllFd(fd, out.items);
        switch (st) {
            .authenticated => {
                try leftover.appendSlice(gpa, accum.items);
                return;
            },
            .need_more => continue,
            .rejected, .failed => return error.AuthFailed,
        }
    }
}

const testing = std.testing;
const client_mod = @import("../client.zig");
const object = @import("../object.zig");
const marshal_t = marshal;
const unmarshal = @import("../unmarshal.zig");

fn daemonThread(d: *Daemon) void {
    d.run();
}

/// Connect with retries: under parallel test binaries the daemon thread can be
/// starved long enough for the one-shot Hello to time out (the documented
/// blocking-auth limitation), so retry to keep these tests reliable.
fn connectRetry(loop: *el.EventLoop, sock: []const u8, uid: u32) !*client_mod.Bus {
    var attempt: usize = 0;
    while (attempt < 20) : (attempt += 1) {
        if (client_mod.Bus.connectUnix(testing.allocator, loop, sock, true, uid)) |b| {
            return b;
        } else |_| {}
    }
    return error.ConnectFailed;
}

const U32Catcher = struct {
    done: bool = false,
    value: u32 = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *U32Catcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        if (r.msg_type != .method_return) return;
        var rd = unmarshal.Reader.init(r.body, r.endian);
        self.value = rd.uint32() catch 0;
    }
};

const StrCatcher = struct {
    done: bool = false,
    buf: [128]u8 = undefined,
    len: usize = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *StrCatcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        if (r.msg_type != .method_return) return;
        var rd = unmarshal.Reader.init(r.body, r.endian);
        const s = rd.string() catch return;
        const n = @min(s.len, self.buf.len);
        @memcpy(self.buf[0..n], s[0..n]);
        self.len = n;
    }
};

const IntCatcher = struct {
    done: bool = false,
    value: i32 = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *IntCatcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        if (r.msg_type != .method_return) return;
        var rd = unmarshal.Reader.init(r.body, r.endian);
        self.value = rd.int32() catch 0;
    }
};

fn echoHandler(ctx: ?*anyopaque, call: *const Message, w: *marshal.Writer) object.HandlerError![]const u8 {
    _ = ctx;
    var r = unmarshal.Reader.init(call.body, call.endian);
    const v = r.int32() catch return error.Failed;
    try w.int32(v);
    return "i";
}

const echo_methods = [_]object.Method{.{ .name = "Echo", .handler = echoHandler }};

const SignalFlag = struct {
    got: bool = false,
    fn onSignal(ctx: ?*anyopaque, b: *client_mod.Bus, sig: *const Message) void {
        _ = b;
        _ = sig;
        const self: *SignalFlag = @ptrCast(@alignCast(ctx.?));
        self.got = true;
    }
};

fn drive(loop: *el.EventLoop, flag: *const bool) void {
    var i: usize = 0;
    while (!flag.* and i < 300) : (i += 1) _ = loop.dispatch(20);
}

test "our client connects to our daemon and Hello works" {
    // The daemon runs on its own thread, so it needs its own allocator (the
    // testing allocator is not thread-safe and the client uses it concurrently).
    var dgpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = dgpa_state.deinit();
    const dgpa = dgpa_state.allocator();

    var dloop = try el.EventLoop.init(dgpa);
    defer dloop.deinit();
    const d = try Daemon.init(dgpa, &dloop);
    defer d.deinit();

    // Unique abstract socket name for this test run.
    var name_buf: [64]u8 = undefined;
    const sock = try std.fmt.bufPrint(&name_buf, "dbuszig-test-{d}", .{linux.getpid()});
    try d.listenUnix(sock, true);

    const thread = try std.Thread.spawn(.{}, daemonThread, .{d});
    defer {
        d.stop();
        thread.join();
    }

    var cloop = try el.EventLoop.init(testing.allocator);
    defer cloop.deinit();
    const client_bus = try connectRetry(&cloop, sock, linux.getuid());
    defer client_bus.deinit();

    const uname = client_bus.unique_name.?;
    try testing.expect(uname.len >= 3);
    try testing.expectEqual(@as(u8, ':'), uname[0]);
}

test "two clients route a call and a signal through our daemon" {
    var dgpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = dgpa_state.deinit();
    const dgpa = dgpa_state.allocator();

    var dloop = try el.EventLoop.init(dgpa);
    defer dloop.deinit();
    const d = try Daemon.init(dgpa, &dloop);
    defer d.deinit();

    var name_buf: [64]u8 = undefined;
    const sock = try std.fmt.bufPrint(&name_buf, "dbuszig-test2-{d}", .{linux.getpid()});
    try d.listenUnix(sock, true);
    const thread = try std.Thread.spawn(.{}, daemonThread, .{d});
    defer {
        d.stop();
        thread.join();
    }

    var cloop = try el.EventLoop.init(testing.allocator);
    defer cloop.deinit();
    const uid = linux.getuid();
    const a = try connectRetry(&cloop, sock, uid);
    defer a.deinit();
    const b = try connectRetry(&cloop, sock, uid);
    defer b.deinit();

    // A exports an Echo object and claims a well-known name.
    try a.exportObject("/test", &.{.{ .name = "t.Echo", .methods = &echo_methods }});
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(testing.allocator);
        var w = marshal.Writer.init(testing.allocator, &body, a.conn.endian);
        try w.string("com.example.Echo");
        try w.uint32(0);
        var rnc = U32Catcher{};
        _ = try a.call(.{ .msg_type = .method_call, .serial = 0, .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "RequestName", .destination = "org.freedesktop.DBus", .body_signature = "su", .body = body.items }, U32Catcher.onReply, &rnc);
        drive(&cloop, &rnc.done);
        try testing.expectEqual(@as(u32, 1), rnc.value); // primary owner
    }

    // B resolves the well-known name to A's unique name.
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(testing.allocator);
        var w = marshal.Writer.init(testing.allocator, &body, b.conn.endian);
        try w.string("com.example.Echo");
        var sc = StrCatcher{};
        _ = try b.call(.{ .msg_type = .method_call, .serial = 0, .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "GetNameOwner", .destination = "org.freedesktop.DBus", .body_signature = "s", .body = body.items }, StrCatcher.onReply, &sc);
        drive(&cloop, &sc.done);
        try testing.expectEqualStrings(a.unique_name.?, sc.buf[0..sc.len]);
    }

    // B calls Echo on the well-known name; the daemon routes it to A and back.
    {
        var body: std.ArrayList(u8) = .empty;
        defer body.deinit(testing.allocator);
        var w = marshal.Writer.init(testing.allocator, &body, b.conn.endian);
        try w.int32(21);
        var ic = IntCatcher{};
        _ = try b.call(.{ .msg_type = .method_call, .serial = 0, .path = "/test", .interface = "t.Echo", .member = "Echo", .destination = "com.example.Echo", .body_signature = "i", .body = body.items }, IntCatcher.onReply, &ic);
        drive(&cloop, &ic.done);
        try testing.expect(ic.done);
        try testing.expectEqual(@as(i32, 21), ic.value);
    }

    // B subscribes to a signal; A emits it; B receives it.
    var flag = SignalFlag{};
    try b.addSignalHandler(.{ .msg_type = .signal, .interface = "t.Sig", .member = "Boom" }, SignalFlag.onSignal, &flag);
    // Flush: round-trip a GetId on B so the daemon has processed the AddMatch.
    {
        var sc = StrCatcher{};
        _ = try b.call(.{ .msg_type = .method_call, .serial = 0, .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "GetId", .destination = "org.freedesktop.DBus" }, StrCatcher.onReply, &sc);
        drive(&cloop, &sc.done);
    }
    _ = try a.emitSignal(.{ .msg_type = .signal, .serial = 0, .path = "/test", .interface = "t.Sig", .member = "Boom" });
    drive(&cloop, &flag.got);
    try testing.expect(flag.got);
}

const ResultCatcher = struct {
    done: bool = false,
    is_error: bool = false,
    value: u32 = 0,
    err_buf: [96]u8 = undefined,
    err_len: usize = 0,
    fn onReply(ctx: ?*anyopaque, conn: *Connection, reply: ?*const Message) void {
        _ = conn;
        const self: *ResultCatcher = @ptrCast(@alignCast(ctx.?));
        defer self.done = true;
        const r = reply orelse return;
        if (r.msg_type == .error_) {
            self.is_error = true;
            if (r.error_name) |nm| {
                const n = @min(nm.len, self.err_buf.len);
                @memcpy(self.err_buf[0..n], nm[0..n]);
                self.err_len = n;
            }
        } else if (r.msg_type == .method_return) {
            var rd = unmarshal.Reader.init(r.body, r.endian);
            self.value = rd.uint32() catch 0;
        }
    }
};

fn requestName(b: *client_mod.Bus, loop: *el.EventLoop, name: []const u8, catcher: *ResultCatcher) !void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &body, b.conn.endian);
    try w.string(name);
    try w.uint32(0);
    _ = try b.call(.{ .msg_type = .method_call, .serial = 0, .path = "/org/freedesktop/DBus", .interface = "org.freedesktop.DBus", .member = "RequestName", .destination = "org.freedesktop.DBus", .body_signature = "su", .body = body.items }, ResultCatcher.onReply, catcher);
    drive(loop, &catcher.done);
}

test "policy denies owning a reserved name" {
    var dgpa_state = std.heap.DebugAllocator(.{}){};
    defer _ = dgpa_state.deinit();
    const dgpa = dgpa_state.allocator();

    var dloop = try el.EventLoop.init(dgpa);
    defer dloop.deinit();
    const d = try Daemon.init(dgpa, &dloop);
    defer d.deinit();

    const cfg = try config_mod.parse(dgpa,
        \\<busconfig>
        \\  <policy context="default">
        \\    <allow own="*"/>
        \\    <deny own="com.reserved.Name"/>
        \\  </policy>
        \\</busconfig>
    );
    d.loadConfig(cfg);

    var name_buf: [64]u8 = undefined;
    const sock = try std.fmt.bufPrint(&name_buf, "dbuszig-pol-{d}", .{linux.getpid()});
    try d.listenUnix(sock, true);
    const thread = try std.Thread.spawn(.{}, daemonThread, .{d});
    defer {
        d.stop();
        thread.join();
    }

    var cloop = try el.EventLoop.init(testing.allocator);
    defer cloop.deinit();
    const a = try connectRetry(&cloop, sock, linux.getuid());
    defer a.deinit();

    var denied = ResultCatcher{};
    try requestName(a, &cloop, "com.reserved.Name", &denied);
    try testing.expect(denied.is_error);
    try testing.expectEqualStrings("org.freedesktop.DBus.Error.AccessDenied", denied.err_buf[0..denied.err_len]);

    var allowed = ResultCatcher{};
    try requestName(a, &cloop, "com.allowed.Name", &allowed);
    try testing.expect(!allowed.is_error);
    try testing.expectEqual(@as(u32, 1), allowed.value); // primary owner
}
