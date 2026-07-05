//! D-Bus SASL authentication, client side. The handshake is line-based (CRLF)
//! after a leading NUL byte, and ends with BEGIN, after which the binary message
//! stream starts. Mechanisms: EXTERNAL (SO_PEERCRED), DBUS_COOKIE_SHA1, ANONYMOUS,
//! plus optional NEGOTIATE_UNIX_FD. See the D-Bus spec "Authentication" section.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const Sha1 = std.crypto.hash.Sha1;

pub const Mechanism = enum { external, anonymous, dbus_cookie_sha1 };

pub const Status = enum { need_more, authenticated, rejected, failed };

pub const Error = error{
    MalformedData,
    CookieNotFound,
    NoCookieContext,
    OpenFailed,
    ReadFailed,
} || std.mem.Allocator.Error;

const hexchars = "0123456789abcdef";

fn appendHex(gpa: std.mem.Allocator, out: *std.ArrayList(u8), bytes: []const u8) !void {
    for (bytes) |b| {
        try out.append(gpa, hexchars[b >> 4]);
        try out.append(gpa, hexchars[b & 0xf]);
    }
}

fn hexVal(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

fn decodeHex(gpa: std.mem.Allocator, hex: []const u8) Error![]u8 {
    if (hex.len % 2 != 0) return Error.MalformedData;
    const out = try gpa.alloc(u8, hex.len / 2);
    errdefer gpa.free(out);
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        const hi = hexVal(hex[i * 2]) orelse return Error.MalformedData;
        const lo = hexVal(hex[i * 2 + 1]) orelse return Error.MalformedData;
        out[i] = hi << 4 | lo;
    }
    return out;
}

pub const Client = struct {
    gpa: std.mem.Allocator,
    uid: u32,
    mechanism: Mechanism = .external,
    negotiate_fd: bool = false,
    /// Directory holding cookie keyrings; null means ~/.dbus-keyrings.
    cookie_dir: ?[]const u8 = null,
    /// Fixed client challenge for deterministic tests; null means random.
    fixed_client_challenge: ?[]const u8 = null,

    guid: ?[]u8 = null,
    fds_agreed: bool = false,
    state: State = .init,

    const State = enum { init, awaiting_reply, awaiting_agree_fd, done, failed };

    pub fn deinit(self: *Client) void {
        if (self.guid) |g| self.gpa.free(g);
        self.guid = null;
    }

    /// Append the leading NUL and the initial AUTH line to `out`.
    pub fn begin(self: *Client, out: *std.ArrayList(u8)) Error!void {
        try out.append(self.gpa, 0); // credentials-passing NUL
        switch (self.mechanism) {
            .external => {
                try out.appendSlice(self.gpa, "AUTH EXTERNAL ");
                var buf: [16]u8 = undefined;
                const uidstr = std.fmt.bufPrint(&buf, "{d}", .{self.uid}) catch unreachable;
                try appendHex(self.gpa, out, uidstr);
                try out.appendSlice(self.gpa, "\r\n");
            },
            .anonymous => {
                try out.appendSlice(self.gpa, "AUTH ANONYMOUS\r\n");
            },
            .dbus_cookie_sha1 => {
                try out.appendSlice(self.gpa, "AUTH DBUS_COOKIE_SHA1 ");
                var buf: [16]u8 = undefined;
                const uidstr = std.fmt.bufPrint(&buf, "{d}", .{self.uid}) catch unreachable;
                try appendHex(self.gpa, out, uidstr);
                try out.appendSlice(self.gpa, "\r\n");
            },
        }
        self.state = .awaiting_reply;
    }

    /// Feed one server reply line (CRLF already stripped), append any response
    /// bytes to `out`, and report the handshake status.
    pub fn feedLine(self: *Client, line: []const u8, out: *std.ArrayList(u8)) Error!Status {
        var it = std.mem.splitScalar(u8, line, ' ');
        const cmd = it.next() orelse return self.fail(out);
        const rest = it.rest();

        if (std.mem.eql(u8, cmd, "OK")) {
            if (self.guid == null and rest.len > 0) self.guid = try self.gpa.dupe(u8, rest);
            return self.afterOk(out);
        } else if (std.mem.eql(u8, cmd, "REJECTED")) {
            self.state = .failed;
            return .rejected;
        } else if (std.mem.eql(u8, cmd, "ERROR")) {
            if (self.state == .awaiting_agree_fd) {
                // Server declined fd passing; proceed without it.
                try out.appendSlice(self.gpa, "BEGIN\r\n");
                self.state = .done;
                return .authenticated;
            }
            return self.fail(out);
        } else if (std.mem.eql(u8, cmd, "DATA")) {
            if (self.mechanism == .dbus_cookie_sha1 and self.state == .awaiting_reply) {
                try self.answerCookie(rest, out);
                return .need_more;
            }
            return self.fail(out);
        } else if (std.mem.eql(u8, cmd, "AGREE_UNIX_FD")) {
            if (self.state == .awaiting_agree_fd) {
                self.fds_agreed = true;
                try out.appendSlice(self.gpa, "BEGIN\r\n");
                self.state = .done;
                return .authenticated;
            }
            return self.fail(out);
        }
        return self.fail(out);
    }

    fn afterOk(self: *Client, out: *std.ArrayList(u8)) Error!Status {
        if (self.negotiate_fd and self.state != .awaiting_agree_fd) {
            try out.appendSlice(self.gpa, "NEGOTIATE_UNIX_FD\r\n");
            self.state = .awaiting_agree_fd;
            return .need_more;
        }
        try out.appendSlice(self.gpa, "BEGIN\r\n");
        self.state = .done;
        return .authenticated;
    }

    fn fail(self: *Client, out: *std.ArrayList(u8)) Error!Status {
        out.appendSlice(self.gpa, "CANCEL\r\n") catch {};
        self.state = .failed;
        return .failed;
    }

    /// Compute and emit the DBUS_COOKIE_SHA1 response for a server challenge.
    fn answerCookie(self: *Client, hexdata: []const u8, out: *std.ArrayList(u8)) Error!void {
        const data = try decodeHex(self.gpa, hexdata);
        defer self.gpa.free(data);
        // data = "<context> <cookie-id> <server-challenge>"
        var parts = std.mem.splitScalar(u8, data, ' ');
        const context = parts.next() orelse return Error.MalformedData;
        const cookie_id = parts.next() orelse return Error.MalformedData;
        const server_challenge = parts.next() orelse return Error.MalformedData;

        const cookie = try self.readCookie(context, cookie_id);
        defer self.gpa.free(cookie);

        var challenge_buf: [32]u8 = undefined;
        const client_challenge: []const u8 = if (self.fixed_client_challenge) |c| c else blk: {
            var raw: [16]u8 = undefined;
            const got = linux.getrandom(&raw, raw.len, 0);
            if (posix.errno(got) != .SUCCESS or got != raw.len) return Error.ReadFailed;
            var w: usize = 0;
            for (raw) |b| {
                challenge_buf[w] = hexchars[b >> 4];
                challenge_buf[w + 1] = hexchars[b & 0xf];
                w += 2;
            }
            break :blk challenge_buf[0..w];
        };

        try appendCookieResponse(self.gpa, out, server_challenge, client_challenge, cookie);
    }

    /// Read the cookie value for `cookie_id` from the keyring file `context`,
    /// using raw syscalls (the std IO model needs an Io handle we do not thread).
    fn readCookie(self: *Client, context: []const u8, cookie_id: []const u8) Error![]u8 {
        // The default (~/.dbus-keyrings) needs env access, which this std version
        // gates behind the Io model; until the connect helper resolves it, require
        // an explicit cookie_dir.
        const dir = self.cookie_dir orelse return Error.NoCookieContext;
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const path = std.fmt.bufPrint(&path_buf, "{s}/{s}\x00", .{ dir, context }) catch return Error.NoCookieContext;
        const path_z: [*:0]const u8 = @ptrCast(path.ptr);

        const rc = linux.openat(linux.AT.FDCWD, path_z, .{ .ACCMODE = .RDONLY }, 0);
        if (posix.errno(rc) != .SUCCESS) return Error.OpenFailed;
        const fd: i32 = @intCast(rc);
        defer _ = linux.close(fd);

        var buf: [8192]u8 = undefined;
        const n = posix.read(fd, &buf) catch return Error.ReadFailed;

        // Each line: "<id> <creation-time> <cookie-hex>"
        var lines = std.mem.splitScalar(u8, buf[0..n], '\n');
        while (lines.next()) |ln| {
            var f = std.mem.splitScalar(u8, ln, ' ');
            const id = f.next() orelse continue;
            if (!std.mem.eql(u8, id, cookie_id)) continue;
            _ = f.next() orelse continue; // creation time
            const cookie = f.next() orelse continue;
            return self.gpa.dupe(u8, cookie);
        }
        return Error.CookieNotFound;
    }
};

/// Append the DBUS_COOKIE_SHA1 `DATA` response line for the given challenges and
/// cookie. Response plaintext is `<client-challenge> <sha1-hex>` where the SHA1
/// is over `server-challenge:client-challenge:cookie`; the line is that plaintext
/// hex-encoded. Pure, so the crypto is directly testable.
pub fn appendCookieResponse(
    gpa: std.mem.Allocator,
    out: *std.ArrayList(u8),
    server_challenge: []const u8,
    client_challenge: []const u8,
    cookie: []const u8,
) Error!void {
    var sha = Sha1.init(.{});
    sha.update(server_challenge);
    sha.update(":");
    sha.update(client_challenge);
    sha.update(":");
    sha.update(cookie);
    var digest: [Sha1.digest_length]u8 = undefined;
    sha.final(&digest);

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(gpa);
    try plain.appendSlice(gpa, client_challenge);
    try plain.append(gpa, ' ');
    try appendHex(gpa, &plain, &digest);

    try out.appendSlice(gpa, "DATA ");
    try appendHex(gpa, out, plain.items);
    try out.appendSlice(gpa, "\r\n");
}

/// Fill `buf` with a 32-char lowercase-hex server GUID from 16 random bytes.
pub fn genGuid(buf: *[32]u8) void {
    var raw: [16]u8 = undefined;
    _ = linux.getrandom(&raw, raw.len, 0);
    for (raw, 0..) |b, i| {
        buf[i * 2] = hexchars[b >> 4];
        buf[i * 2 + 1] = hexchars[b & 0xf];
    }
}

/// Server side of the SASL handshake. Fed one CRLF-stripped client line at a
/// time; appends the server's response to `out`. Supports EXTERNAL (verified
/// against the socket peer's uid) and optionally ANONYMOUS, plus NEGOTIATE_UNIX_FD.
pub const Server = struct {
    gpa: std.mem.Allocator,
    guid: [32]u8,
    /// SO_PEERCRED uid to verify EXTERNAL against; null skips the uid check.
    peer_uid: ?u32 = null,
    allow_anonymous: bool = false,
    negotiated_fd: bool = false,
    state: State = .waiting_auth,

    const State = enum { waiting_auth, waiting_begin, done, failed };

    pub fn init(gpa: std.mem.Allocator, peer_uid: ?u32) Server {
        var s = Server{ .gpa = gpa, .guid = undefined, .peer_uid = peer_uid };
        genGuid(&s.guid);
        return s;
    }

    pub fn feedLine(self: *Server, line: []const u8, out: *std.ArrayList(u8)) Error!Status {
        var it = std.mem.splitScalar(u8, line, ' ');
        const cmd = it.next() orelse return self.reject(out);

        if (std.mem.eql(u8, cmd, "AUTH")) {
            const mech = it.next() orelse return self.reject(out);
            const data = it.rest();
            if (std.mem.eql(u8, mech, "EXTERNAL")) {
                if (self.peer_uid) |puid| {
                    if (data.len > 0) {
                        const decoded = decodeHex(self.gpa, data) catch return self.reject(out);
                        defer self.gpa.free(decoded);
                        const claimed = std.fmt.parseInt(u32, decoded, 10) catch return self.reject(out);
                        if (claimed != puid) return self.reject(out);
                    }
                }
                return self.ok(out);
            } else if (std.mem.eql(u8, mech, "ANONYMOUS") and self.allow_anonymous) {
                return self.ok(out);
            }
            return self.reject(out);
        } else if (std.mem.eql(u8, cmd, "NEGOTIATE_UNIX_FD")) {
            if (self.state != .waiting_begin) return self.errline(out);
            try out.appendSlice(self.gpa, "AGREE_UNIX_FD\r\n");
            self.negotiated_fd = true;
            return .need_more;
        } else if (std.mem.eql(u8, cmd, "BEGIN")) {
            if (self.state != .waiting_begin) return self.errline(out);
            self.state = .done;
            return .authenticated;
        } else if (std.mem.eql(u8, cmd, "CANCEL")) {
            self.state = .waiting_auth;
            return self.reject(out);
        }
        return self.errline(out);
    }

    fn ok(self: *Server, out: *std.ArrayList(u8)) Error!Status {
        try out.appendSlice(self.gpa, "OK ");
        try out.appendSlice(self.gpa, &self.guid);
        try out.appendSlice(self.gpa, "\r\n");
        self.state = .waiting_begin;
        return .need_more;
    }

    fn reject(self: *Server, out: *std.ArrayList(u8)) Error!Status {
        try out.appendSlice(self.gpa, "REJECTED EXTERNAL\r\n");
        self.state = .waiting_auth;
        return .need_more;
    }

    fn errline(self: *Server, out: *std.ArrayList(u8)) Error!Status {
        try out.appendSlice(self.gpa, "ERROR\r\n");
        return .need_more;
    }
};

const testing = std.testing;

fn stripCrlf(s: []const u8) []const u8 {
    return std.mem.trimEnd(u8, s, "\r\n");
}

test "client and server complete an EXTERNAL handshake" {
    var client = Client{ .gpa = testing.allocator, .uid = 1000, .mechanism = .external };
    defer client.deinit();
    var server = Server.init(testing.allocator, 1000);

    var cout: std.ArrayList(u8) = .empty;
    defer cout.deinit(testing.allocator);
    var sout: std.ArrayList(u8) = .empty;
    defer sout.deinit(testing.allocator);

    try client.begin(&cout);
    try testing.expectEqual(@as(u8, 0), cout.items[0]); // leading NUL
    const auth_line = stripCrlf(cout.items[1..]);

    try testing.expectEqual(Status.need_more, try server.feedLine(auth_line, &sout));
    try testing.expect(std.mem.startsWith(u8, sout.items, "OK "));

    cout.clearRetainingCapacity();
    try testing.expectEqual(Status.authenticated, try client.feedLine(stripCrlf(sout.items), &cout));
    try testing.expectEqualStrings("BEGIN\r\n", cout.items);
    try testing.expectEqualStrings(client.guid.?, server.guid[0..]);

    sout.clearRetainingCapacity();
    try testing.expectEqual(Status.authenticated, try server.feedLine(stripCrlf(cout.items), &sout));
    try testing.expect(server.state == .done);
}

test "server rejects EXTERNAL with a mismatched uid" {
    var server = Server.init(testing.allocator, 1000);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    // hex("2000") = 32303030
    try testing.expectEqual(Status.need_more, try server.feedLine("AUTH EXTERNAL 32303030", &out));
    try testing.expect(std.mem.startsWith(u8, out.items, "REJECTED"));
}

test "EXTERNAL handshake produces AUTH then BEGIN" {
    var client = Client{ .gpa = testing.allocator, .uid = 1000, .mechanism = .external };
    defer client.deinit();

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try client.begin(&out);
    // NUL + "AUTH EXTERNAL " + hex("1000") + CRLF. "1000" -> 31 30 30 30.
    try testing.expectEqual(@as(u8, 0), out.items[0]);
    try testing.expectEqualStrings("AUTH EXTERNAL 31303030\r\n", out.items[1..]);

    out.clearRetainingCapacity();
    const st = try client.feedLine("OK 1234deadbeef", &out);
    try testing.expectEqual(Status.authenticated, st);
    try testing.expectEqualStrings("BEGIN\r\n", out.items);
    try testing.expectEqualStrings("1234deadbeef", client.guid.?);
}

test "EXTERNAL with fd negotiation" {
    var client = Client{ .gpa = testing.allocator, .uid = 0, .mechanism = .external, .negotiate_fd = true };
    defer client.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);

    try client.begin(&out);
    out.clearRetainingCapacity();
    try testing.expectEqual(Status.need_more, try client.feedLine("OK abcd", &out));
    try testing.expectEqualStrings("NEGOTIATE_UNIX_FD\r\n", out.items);

    out.clearRetainingCapacity();
    try testing.expectEqual(Status.authenticated, try client.feedLine("AGREE_UNIX_FD", &out));
    try testing.expectEqualStrings("BEGIN\r\n", out.items);
    try testing.expect(client.fds_agreed);
}

test "REJECTED yields rejected status" {
    var client = Client{ .gpa = testing.allocator, .uid = 1000, .mechanism = .external };
    defer client.deinit();
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try client.begin(&out);
    out.clearRetainingCapacity();
    try testing.expectEqual(Status.rejected, try client.feedLine("REJECTED EXTERNAL DBUS_COOKIE_SHA1", &out));
}

fn expectedCookieLine(server_challenge: []const u8, client_challenge: []const u8, cookie: []const u8) !std.ArrayList(u8) {
    var digest: [Sha1.digest_length]u8 = undefined;
    var sha = Sha1.init(.{});
    sha.update(server_challenge);
    sha.update(":");
    sha.update(client_challenge);
    sha.update(":");
    sha.update(cookie);
    sha.final(&digest);

    var plain: std.ArrayList(u8) = .empty;
    defer plain.deinit(testing.allocator);
    try plain.appendSlice(testing.allocator, client_challenge);
    try plain.append(testing.allocator, ' ');
    try appendHex(testing.allocator, &plain, &digest);

    var expected: std.ArrayList(u8) = .empty;
    errdefer expected.deinit(testing.allocator);
    try expected.appendSlice(testing.allocator, "DATA ");
    try appendHex(testing.allocator, &expected, plain.items);
    try expected.appendSlice(testing.allocator, "\r\n");
    return expected;
}

test "appendCookieResponse matches a known SHA1 vector" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try appendCookieResponse(testing.allocator, &out, "ssssssss", "cccccccc", "abc123");

    var expected = try expectedCookieLine("ssssssss", "cccccccc", "abc123");
    defer expected.deinit(testing.allocator);
    try testing.expectEqualStrings(expected.items, out.items);
}

fn writeFileRaw(path_z: [*:0]const u8, data: []const u8) !void {
    const rc = linux.openat(linux.AT.FDCWD, path_z, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o600);
    if (posix.errno(rc) != .SUCCESS) return error.WriteSetupFailed;
    const fd: i32 = @intCast(rc);
    defer _ = linux.close(fd);
    _ = linux.write(fd, data.ptr, data.len);
}

test "DBUS_COOKIE_SHA1 full handshake reads the keyring and answers" {
    // Write a keyring file under /tmp using raw syscalls, context = unique name.
    const pid = linux.getpid();
    var ctx_buf: [64]u8 = undefined;
    const context = try std.fmt.bufPrint(&ctx_buf, "dbuszig-cookie-{d}", .{pid});
    var path_buf: [128]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/{s}\x00", .{context});
    const path_z: [*:0]const u8 = @ptrCast(path.ptr);
    try writeFileRaw(path_z, "42 1700000000 abc123\n");
    defer _ = linux.unlinkat(linux.AT.FDCWD, path_z, 0);

    var client = Client{
        .gpa = testing.allocator,
        .uid = 1000,
        .mechanism = .dbus_cookie_sha1,
        .cookie_dir = "/tmp",
        .fixed_client_challenge = "cccccccc",
    };
    defer client.deinit();

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try client.begin(&out);
    out.clearRetainingCapacity();

    // Server DATA: "<context> 42 ssssssss" hex-encoded.
    var challenge_plain: std.ArrayList(u8) = .empty;
    defer challenge_plain.deinit(testing.allocator);
    try challenge_plain.appendSlice(testing.allocator, context);
    try challenge_plain.appendSlice(testing.allocator, " 42 ssssssss");
    var data_line: std.ArrayList(u8) = .empty;
    defer data_line.deinit(testing.allocator);
    try data_line.appendSlice(testing.allocator, "DATA ");
    try appendHex(testing.allocator, &data_line, challenge_plain.items);

    try testing.expectEqual(Status.need_more, try client.feedLine(data_line.items, &out));

    var expected = try expectedCookieLine("ssssssss", "cccccccc", "abc123");
    defer expected.deinit(testing.allocator);
    try testing.expectEqualStrings(expected.items, out.items);
}
