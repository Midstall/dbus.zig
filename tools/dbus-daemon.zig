//! Minimal pure-Zig dbus-daemon: listens on /tmp/dbuszig-daemon-<pid>.sock and
//! prints its address (`unix:path=...`) to stdout once bound, then serves. Env
//! and argv access are gated behind the new std Io model, so the socket path is
//! derived from the pid instead of taken from arguments.

const std = @import("std");
const linux = std.os.linux;
const dbus = @import("dbus");

pub fn main() void {
    const gpa = std.heap.page_allocator;
    const pid = linux.getpid();

    var path_buf: [96]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/tmp/dbuszig-daemon-{d}.sock", .{pid}) catch return;

    // Remove any stale socket file from a previous run with the same pid.
    var z_buf: [98]u8 = undefined;
    const pz = std.fmt.bufPrint(&z_buf, "{s}\x00", .{path}) catch return;
    _ = linux.unlinkat(linux.AT.FDCWD, @ptrCast(pz.ptr), 0);

    var loop = dbus.event_loop.EventLoop.init(gpa) catch return;
    const d = dbus.daemon.bus.Daemon.init(gpa, &loop) catch return;
    d.listenUnix(path, false) catch |e| {
        var eb: [64]u8 = undefined;
        const es = std.fmt.bufPrint(&eb, "listen failed: {s}\n", .{@errorName(e)}) catch return;
        _ = linux.write(2, es.ptr, es.len);
        return;
    };

    // Announce readiness only after the socket is bound and listening.
    var line_buf: [128]u8 = undefined;
    const line = std.fmt.bufPrint(&line_buf, "unix:path={s}\n", .{path}) catch return;
    _ = linux.write(1, line.ptr, line.len);

    d.run();
}
