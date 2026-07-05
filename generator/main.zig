//! dbus-gen: read a D-Bus introspection XML file and emit a Zig bindings module.
//! Usage (as wired by build.zig): `dbus-gen <input.xml> <output.zig>`. File IO uses
//! raw syscalls (the std Io model needs an Io handle we do not thread); argv comes
//! from the minimal process-init parameter.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const introspect = @import("introspect.zig");
const codegen = @import("codegen.zig");

pub fn main(init: std.process.Init.Minimal) !void {
    const gpa = std.heap.page_allocator;

    var it = std.process.Args.Iterator.init(init.args);
    _ = it.next(); // program name
    const input = it.next() orelse return error.MissingInput;
    const output = it.next() orelse return error.MissingOutput;

    const xml = try readFileZ(gpa, input);
    defer gpa.free(xml);

    var doc = try introspect.parse(gpa, xml);
    defer doc.deinit();

    const src = try codegen.generate(gpa, doc);
    defer gpa.free(src);

    try writeFileZ(output, src);
}

fn readFileZ(gpa: std.mem.Allocator, path: [*:0]const u8) ![]u8 {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    if (posix.errno(rc) != .SUCCESS) return error.OpenFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);

    var data: std.ArrayList(u8) = .empty;
    errdefer data.deinit(gpa);
    var buf: [8192]u8 = undefined;
    while (true) {
        const n = posix.read(fd, &buf) catch return error.ReadFailed;
        if (n == 0) break;
        try data.appendSlice(gpa, buf[0..n]);
    }
    return data.toOwnedSlice(gpa);
}

fn writeFileZ(path: [*:0]const u8, bytes: []const u8) !void {
    const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (posix.errno(rc) != .SUCCESS) return error.OpenFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    var off: usize = 0;
    while (off < bytes.len) {
        const w = linux.write(fd, bytes[off..].ptr, bytes.len - off);
        if (posix.errno(w) != .SUCCESS) return error.WriteFailed;
        const n: usize = @intCast(w);
        if (n == 0) return error.WriteFailed;
        off += n;
    }
}
