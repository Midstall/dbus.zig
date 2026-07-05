//! A small epoll-based event loop for file-descriptor readiness, modelled on
//! wayland.zig's event_loop but pared down to the fd sources a D-Bus connection
//! needs. Sources removed during dispatch are freed after the ready set is
//! processed, so a callback may safely remove its own source.
//!
//! Raw Linux syscalls via std.os.linux; errno via std.posix.errno. Zig 0.16.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const READABLE: u32 = 0x01;
pub const WRITABLE: u32 = 0x02;
pub const HANGUP: u32 = 0x04;
pub const ERROR: u32 = 0x08;

/// fd readiness callback: `mask` is the OR of the READABLE/WRITABLE/HANGUP/ERROR
/// flags above.
pub const Callback = *const fn (mask: u32, data: ?*anyopaque) void;

pub const Error = error{
    EpollCreateFailed,
    EpollCtlFailed,
} || std.mem.Allocator.Error;

pub const Source = struct {
    loop: *EventLoop,
    fd: i32,
    callback: Callback,
    data: ?*anyopaque,
    removed: bool = false,
};

fn maskToEpoll(mask: u32) u32 {
    var e: u32 = 0;
    if (mask & READABLE != 0) e |= linux.EPOLL.IN;
    if (mask & WRITABLE != 0) e |= linux.EPOLL.OUT;
    return e;
}

fn epollToMask(events: u32) u32 {
    var m: u32 = 0;
    if (events & linux.EPOLL.IN != 0) m |= READABLE;
    if (events & linux.EPOLL.OUT != 0) m |= WRITABLE;
    if (events & linux.EPOLL.HUP != 0) m |= HANGUP;
    if (events & linux.EPOLL.ERR != 0) m |= ERROR;
    return m;
}

pub const EventLoop = struct {
    gpa: std.mem.Allocator,
    epfd: i32,
    sources: std.ArrayList(*Source),
    to_free: std.ArrayList(*Source),
    /// Nesting depth of `dispatch`; deferred sources are freed only when it
    /// returns to 0, so a callback that re-enters `dispatch` stays safe.
    dispatch_depth: u32 = 0,

    pub fn init(gpa: std.mem.Allocator) Error!EventLoop {
        const rc = linux.epoll_create1(linux.EPOLL.CLOEXEC);
        if (posix.errno(rc) != .SUCCESS) return Error.EpollCreateFailed;
        return .{
            .gpa = gpa,
            .epfd = @intCast(rc),
            .sources = .empty,
            .to_free = .empty,
        };
    }

    pub fn deinit(self: *EventLoop) void {
        for (self.sources.items) |src| self.gpa.destroy(src);
        for (self.to_free.items) |src| self.gpa.destroy(src);
        self.sources.deinit(self.gpa);
        self.to_free.deinit(self.gpa);
        _ = linux.close(self.epfd);
    }

    pub fn addFd(self: *EventLoop, fd: i32, mask: u32, callback: Callback, data: ?*anyopaque) Error!*Source {
        const src = try self.gpa.create(Source);
        errdefer self.gpa.destroy(src);
        src.* = .{ .loop = self, .fd = fd, .callback = callback, .data = data };
        var ev = linux.epoll_event{ .events = maskToEpoll(mask), .data = .{ .ptr = @intFromPtr(src) } };
        const rc = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_ADD, fd, &ev);
        if (posix.errno(rc) != .SUCCESS) return Error.EpollCtlFailed;
        try self.sources.append(self.gpa, src);
        return src;
    }

    pub fn updateFd(self: *EventLoop, src: *Source, mask: u32) Error!void {
        var ev = linux.epoll_event{ .events = maskToEpoll(mask), .data = .{ .ptr = @intFromPtr(src) } };
        const rc = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_MOD, src.fd, &ev);
        if (posix.errno(rc) != .SUCCESS) return Error.EpollCtlFailed;
    }

    pub fn remove(self: *EventLoop, src: *Source) void {
        if (src.removed) return;
        src.removed = true;
        _ = linux.epoll_ctl(self.epfd, linux.EPOLL.CTL_DEL, src.fd, null);
        for (self.sources.items, 0..) |s, i| {
            if (s == src) {
                _ = self.sources.swapRemove(i);
                break;
            }
        }
        if (self.dispatch_depth > 0) {
            self.to_free.append(self.gpa, src) catch {};
        } else {
            self.gpa.destroy(src);
        }
    }

    /// Wait up to `timeout_ms` (-1 = block) and dispatch ready sources. Returns
    /// the number of ready events processed.
    pub fn dispatch(self: *EventLoop, timeout_ms: i32) usize {
        var events: [32]linux.epoll_event = undefined;
        const rc = linux.epoll_wait(self.epfd, &events, events.len, timeout_ms);
        if (posix.errno(rc) != .SUCCESS) return 0; // includes EINTR
        const n: usize = @intCast(rc);
        self.dispatch_depth += 1;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const src: *Source = @ptrFromInt(events[i].data.ptr);
            if (src.removed) continue;
            src.callback(epollToMask(events[i].events), src.data);
        }
        self.dispatch_depth -= 1;
        if (self.dispatch_depth == 0) {
            for (self.to_free.items) |src| self.gpa.destroy(src);
            self.to_free.clearRetainingCapacity();
        }
        return n;
    }
};

const testing = std.testing;

const Counter = struct {
    n: usize = 0,
    fn cb(mask: u32, data: ?*anyopaque) void {
        _ = mask;
        const self: *Counter = @ptrCast(@alignCast(data.?));
        self.n += 1;
    }
};

const SelfRemover = struct {
    loop: *EventLoop,
    src: ?*Source = null,
    n: usize = 0,
    fn cb(mask: u32, data: ?*anyopaque) void {
        _ = mask;
        const self: *SelfRemover = @ptrCast(@alignCast(data.?));
        self.n += 1;
        if (self.src) |s| self.loop.remove(s); // remove while dispatching
    }
};

test "a source removing itself during dispatch is safe" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    const efd_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    const efd: i32 = @intCast(efd_rc);
    defer _ = linux.close(efd);

    var sr = SelfRemover{ .loop = &loop };
    sr.src = try loop.addFd(efd, READABLE, SelfRemover.cb, &sr);
    const one: u64 = 1;
    _ = linux.write(efd, std.mem.asBytes(&one), 8);
    _ = loop.dispatch(100);
    try testing.expectEqual(@as(usize, 1), sr.n);

    // The source freed itself via the deferred-free path; firing again is a no-op.
    _ = linux.write(efd, std.mem.asBytes(&one), 8);
    _ = loop.dispatch(50);
    try testing.expectEqual(@as(usize, 1), sr.n);
}

test "fd readiness fires the callback and remove stops it" {
    var loop = try EventLoop.init(testing.allocator);
    defer loop.deinit();

    const efd_rc = linux.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    try testing.expectEqual(linux.E.SUCCESS, posix.errno(efd_rc));
    const efd: i32 = @intCast(efd_rc);
    defer _ = linux.close(efd);

    var counter = Counter{};
    const src = try loop.addFd(efd, READABLE, Counter.cb, &counter);

    const one: u64 = 1;
    _ = linux.write(efd, std.mem.asBytes(&one), 8);
    _ = loop.dispatch(100);
    try testing.expectEqual(@as(usize, 1), counter.n);

    // Drain, remove, signal again: the callback must not fire.
    var drain: u64 = undefined;
    _ = try posix.read(efd, std.mem.asBytes(&drain));
    loop.remove(src);
    _ = linux.write(efd, std.mem.asBytes(&one), 8);
    _ = loop.dispatch(50);
    try testing.expectEqual(@as(usize, 1), counter.n);
}
