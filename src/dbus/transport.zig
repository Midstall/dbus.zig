//! D-Bus byte transport over a stream socket (unix or tcp), with SCM_RIGHTS
//! ancillary fd passing for the UNIX_FD type. Non-blocking; the connection layer
//! drives readiness via the event loop.
//!
//! Raw Linux syscalls via std.os.linux; errno via std.posix.errno. Zig 0.16.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const Error = error{
    SocketFailed,
    ConnectFailed,
    WouldBlock,
    Interrupted,
    ConnectionReset,
    BrokenPipe,
    PathTooLong,
    TooManyFds,
    Unexpected,
};

/// Max fds carried in a single message's ancillary data.
pub const max_fds = 16;

const cmsg_align_to = @sizeOf(usize);

fn cmsgAlign(n: usize) usize {
    return (n + cmsg_align_to - 1) & ~@as(usize, cmsg_align_to - 1);
}

const cmsg_hdr_space = cmsgAlign(@sizeOf(linux.cmsghdr));
const cmsg_buf_len = cmsg_hdr_space + cmsgAlign(max_fds * @sizeOf(i32));

fn check(rc: usize) Error!usize {
    return switch (posix.errno(rc)) {
        .SUCCESS => rc,
        .AGAIN => Error.WouldBlock,
        .INTR => Error.Interrupted,
        .CONNRESET => Error.ConnectionReset,
        .PIPE => Error.BrokenPipe,
        else => Error.Unexpected,
    };
}

pub const RecvResult = struct {
    bytes: usize,
    fds: usize,
};

pub const Transport = struct {
    fd: i32,

    pub fn fromFd(fd: i32) Transport {
        return .{ .fd = fd };
    }

    pub fn close(self: *Transport) void {
        _ = linux.close(self.fd);
        self.fd = -1;
    }

    /// Connect a stream unix socket. `abstract` selects the Linux abstract
    /// namespace (leading NUL) instead of a filesystem path.
    pub fn connectUnix(path: []const u8, abstract: bool) Error!Transport {
        const s = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0);
        _ = try check(s);
        const fd: i32 = @intCast(s);
        errdefer _ = linux.close(fd);

        var addr: linux.sockaddr.un = .{ .family = linux.AF.UNIX, .path = undefined };
        const path_off = @offsetOf(linux.sockaddr.un, "path");
        var namelen: usize = path_off;
        if (abstract) {
            if (1 + path.len > addr.path.len) return Error.PathTooLong;
            addr.path[0] = 0;
            @memcpy(addr.path[1 .. 1 + path.len], path);
            namelen += 1 + path.len;
        } else {
            if (path.len + 1 > addr.path.len) return Error.PathTooLong;
            @memcpy(addr.path[0..path.len], path);
            addr.path[path.len] = 0;
            namelen += path.len + 1;
        }
        const rc = linux.connect(fd, @ptrCast(&addr), @intCast(namelen));
        _ = check(rc) catch return Error.ConnectFailed;
        return .{ .fd = fd };
    }

    pub fn setNonblock(self: *Transport, on: bool) Error!void {
        const flags = linux.fcntl(self.fd, linux.F.GETFL, 0);
        _ = try check(flags);
        var f: usize = flags;
        if (on) f |= @as(usize, 1) << @bitOffsetOf(linux.O, "NONBLOCK") else f &= ~(@as(usize, 1) << @bitOffsetOf(linux.O, "NONBLOCK"));
        _ = try check(linux.fcntl(self.fd, linux.F.SETFL, f));
    }

    pub fn write(self: *Transport, bytes: []const u8) Error!usize {
        return check(linux.write(self.fd, bytes.ptr, bytes.len));
    }

    pub fn read(self: *Transport, buf: []u8) Error!usize {
        return check(linux.read(self.fd, buf.ptr, buf.len));
    }

    /// Send bytes plus `fds` as SCM_RIGHTS ancillary data. Returns bytes sent.
    pub fn sendWithFds(self: *Transport, bytes: []const u8, fds: []const i32) Error!usize {
        if (fds.len > max_fds) return Error.TooManyFds;
        var iov = [1]posix.iovec_const{.{ .base = bytes.ptr, .len = bytes.len }};

        var cmsg_buf: [cmsg_buf_len]u8 align(cmsg_align_to) = undefined;
        var controllen: usize = 0;
        var control_ptr: ?*const anyopaque = null;
        if (fds.len > 0) {
            const data_len = fds.len * @sizeOf(i32);
            controllen = cmsg_hdr_space + cmsgAlign(data_len);
            const hdr: *linux.cmsghdr = @ptrCast(@alignCast(&cmsg_buf));
            hdr.* = .{
                .len = cmsg_hdr_space + data_len,
                .level = linux.SOL.SOCKET,
                .type = linux.SCM.RIGHTS,
            };
            @memcpy(cmsg_buf[cmsg_hdr_space .. cmsg_hdr_space + data_len], std.mem.sliceAsBytes(fds));
            control_ptr = &cmsg_buf;
        }

        var msg = linux.msghdr_const{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = control_ptr,
            .controllen = controllen,
            .flags = 0,
        };
        return check(linux.sendmsg(self.fd, &msg, 0));
    }

    /// Receive bytes and any SCM_RIGHTS fds into `fd_out` (O_CLOEXEC set).
    pub fn recvWithFds(self: *Transport, buf: []u8, fd_out: []i32) Error!RecvResult {
        var iov = [1]posix.iovec{.{ .base = buf.ptr, .len = buf.len }};
        var cmsg_buf: [cmsg_buf_len]u8 align(cmsg_align_to) = undefined;
        var msg = linux.msghdr{
            .name = null,
            .namelen = 0,
            .iov = &iov,
            .iovlen = 1,
            .control = &cmsg_buf,
            .controllen = cmsg_buf.len,
            .flags = 0,
        };
        const n = try check(linux.recvmsg(self.fd, &msg, MSG_CMSG_CLOEXEC));

        var nfds: usize = 0;
        if (msg.controllen >= cmsg_hdr_space) {
            const hdr: *const linux.cmsghdr = @ptrCast(@alignCast(&cmsg_buf));
            if (hdr.level == linux.SOL.SOCKET and hdr.type == linux.SCM.RIGHTS) {
                const data_len = hdr.len - cmsg_hdr_space;
                const count = data_len / @sizeOf(i32);
                const fd_bytes = cmsg_buf[cmsg_hdr_space .. cmsg_hdr_space + count * @sizeOf(i32)];
                const take = @min(count, fd_out.len);
                @memcpy(std.mem.sliceAsBytes(fd_out[0..take]), fd_bytes[0 .. take * @sizeOf(i32)]);
                // Any fds beyond fd_out's capacity were still installed by the
                // kernel; close them so they are not leaked.
                var k = take;
                while (k < count) : (k += 1) {
                    var fdv: i32 = undefined;
                    @memcpy(std.mem.asBytes(&fdv), fd_bytes[k * @sizeOf(i32) .. (k + 1) * @sizeOf(i32)]);
                    _ = linux.close(fdv);
                }
                nfds = take;
            }
        }
        // Ancillary data truncated: the peer sent more fds than our buffer holds.
        if (msg.flags & MSG_CTRUNC != 0) return Error.TooManyFds;
        return .{ .bytes = n, .fds = nfds };
    }
};

const MSG_CMSG_CLOEXEC: u32 = 0x40000000;
const MSG_CTRUNC: u32 = 0x0008;

const testing = std.testing;

fn socketpair() Error![2]i32 {
    var fds: [2]i32 = undefined;
    _ = try check(linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM | linux.SOCK.CLOEXEC, 0, &fds));
    return fds;
}

test "byte roundtrip over a socketpair" {
    const fds = try socketpair();
    var a = Transport.fromFd(fds[0]);
    var b = Transport.fromFd(fds[1]);
    defer a.close();
    defer b.close();

    const sent = try a.write("hello");
    try testing.expectEqual(@as(usize, 5), sent);

    var buf: [16]u8 = undefined;
    const n = try b.read(buf[0..]);
    try testing.expectEqualStrings("hello", buf[0..n]);
}

test "pass a file descriptor over SCM_RIGHTS" {
    const main = try socketpair();
    var a = Transport.fromFd(main[0]);
    var b = Transport.fromFd(main[1]);
    defer a.close();
    defer b.close();

    // Pass one end of an auxiliary socketpair; prove the received fd refers to
    // the same socket by writing to its peer and reading from the received fd.
    const aux = try socketpair();
    var aux_peer = Transport.fromFd(aux[1]);
    defer aux_peer.close();

    _ = try a.sendWithFds("f", &.{aux[0]});
    _ = linux.close(aux[0]); // sender no longer needs it

    var buf: [8]u8 = undefined;
    var got_fds: [4]i32 = undefined;
    const res = try b.recvWithFds(buf[0..], got_fds[0..]);
    try testing.expectEqual(@as(usize, 1), res.bytes);
    try testing.expectEqual(@as(usize, 1), res.fds);
    try testing.expectEqualStrings("f", buf[0..1]);

    var recv_end = Transport.fromFd(got_fds[0]);
    defer recv_end.close();
    _ = try aux_peer.write("z");
    var buf2: [8]u8 = undefined;
    const n = try recv_end.read(buf2[0..]);
    try testing.expectEqualStrings("z", buf2[0..n]);
}
