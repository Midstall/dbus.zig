//! D-Bus server address parsing. An address is one or more `transport:key=val,...`
//! entries separated by `;`. Values are `%XX`-escaped. See the D-Bus spec's
//! "Server Addresses" section.

const std = @import("std");

pub const Error = error{
    InvalidAddress,
    UnknownTransport,
    InvalidEscape,
    InvalidPort,
} || std.mem.Allocator.Error;

pub const Kind = enum { unix, tcp, nonce_tcp };

/// One parsed server address. String fields are heap-allocated and released by
/// `deinit`. Only the fields relevant to `kind` are populated.
pub const ServerAddress = struct {
    kind: Kind,
    path: ?[]const u8 = null,
    abstract: ?[]const u8 = null,
    host: ?[]const u8 = null,
    port: ?u16 = null,
    family: ?[]const u8 = null,
    noncefile: ?[]const u8 = null,
    guid: ?[]const u8 = null,

    pub fn deinit(self: ServerAddress, gpa: std.mem.Allocator) void {
        inline for (.{ self.path, self.abstract, self.host, self.family, self.noncefile, self.guid }) |maybe| {
            if (maybe) |s| gpa.free(s);
        }
    }
};

/// A parsed address list. `deinit` frees every entry and the backing slice.
pub const List = struct {
    items: []ServerAddress,

    pub fn deinit(self: List, gpa: std.mem.Allocator) void {
        for (self.items) |a| a.deinit(gpa);
        gpa.free(self.items);
    }
};

fn hexDigit(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Decode a `%XX`-escaped address value into a freshly-allocated slice.
fn unescape(gpa: std.mem.Allocator, v: []const u8) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < v.len) {
        if (v[i] == '%') {
            if (i + 2 >= v.len) return Error.InvalidEscape;
            const hi = hexDigit(v[i + 1]) orelse return Error.InvalidEscape;
            const lo = hexDigit(v[i + 2]) orelse return Error.InvalidEscape;
            try out.append(gpa, hi << 4 | lo);
            i += 3;
        } else {
            try out.append(gpa, v[i]);
            i += 1;
        }
    }
    return out.toOwnedSlice(gpa);
}

fn parseOne(gpa: std.mem.Allocator, entry: []const u8) Error!ServerAddress {
    const colon = std.mem.indexOfScalar(u8, entry, ':') orelse return Error.InvalidAddress;
    const transport = entry[0..colon];
    const kind: Kind = if (std.mem.eql(u8, transport, "unix"))
        .unix
    else if (std.mem.eql(u8, transport, "tcp"))
        .tcp
    else if (std.mem.eql(u8, transport, "nonce-tcp"))
        .nonce_tcp
    else
        return Error.UnknownTransport;

    var addr = ServerAddress{ .kind = kind };
    errdefer addr.deinit(gpa);

    var kv_it = std.mem.splitScalar(u8, entry[colon + 1 ..], ',');
    while (kv_it.next()) |kv| {
        if (kv.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse return Error.InvalidAddress;
        const key = kv[0..eq];
        const val = try unescape(gpa, kv[eq + 1 ..]);
        var consumed = false;
        defer if (!consumed) gpa.free(val);

        if (std.mem.eql(u8, key, "path")) {
            addr.path = val;
            consumed = true;
        } else if (std.mem.eql(u8, key, "abstract")) {
            addr.abstract = val;
            consumed = true;
        } else if (std.mem.eql(u8, key, "host")) {
            addr.host = val;
            consumed = true;
        } else if (std.mem.eql(u8, key, "family")) {
            addr.family = val;
            consumed = true;
        } else if (std.mem.eql(u8, key, "noncefile")) {
            addr.noncefile = val;
            consumed = true;
        } else if (std.mem.eql(u8, key, "guid")) {
            addr.guid = val;
            consumed = true;
        } else if (std.mem.eql(u8, key, "port")) {
            addr.port = std.fmt.parseInt(u16, val, 10) catch return Error.InvalidPort;
            // val not stored; freed by the defer.
        }
        // Unknown keys are ignored (val freed by the defer).
    }
    return addr;
}

/// Parse a full address list (`;`-separated).
pub fn parse(gpa: std.mem.Allocator, s: []const u8) Error!List {
    var list: std.ArrayList(ServerAddress) = .empty;
    errdefer {
        for (list.items) |a| a.deinit(gpa);
        list.deinit(gpa);
    }
    var it = std.mem.splitScalar(u8, s, ';');
    while (it.next()) |entry| {
        if (entry.len == 0) continue;
        const addr = try parseOne(gpa, entry);
        try list.append(gpa, addr);
    }
    if (list.items.len == 0) return Error.InvalidAddress;
    return .{ .items = try list.toOwnedSlice(gpa) };
}

const testing = std.testing;

test "parse a unix path address" {
    var list = try parse(testing.allocator, "unix:path=/run/user/1000/bus");
    defer list.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 1), list.items.len);
    try testing.expectEqual(Kind.unix, list.items[0].kind);
    try testing.expectEqualStrings("/run/user/1000/bus", list.items[0].path.?);
}

test "parse abstract socket with guid" {
    var list = try parse(testing.allocator, "unix:abstract=/tmp/dbus-abc,guid=deadbeef");
    defer list.deinit(testing.allocator);
    try testing.expectEqualStrings("/tmp/dbus-abc", list.items[0].abstract.?);
    try testing.expectEqualStrings("deadbeef", list.items[0].guid.?);
}

test "parse tcp host and port" {
    var list = try parse(testing.allocator, "tcp:host=localhost,port=12345,family=ipv4");
    defer list.deinit(testing.allocator);
    try testing.expectEqual(Kind.tcp, list.items[0].kind);
    try testing.expectEqualStrings("localhost", list.items[0].host.?);
    try testing.expectEqual(@as(u16, 12345), list.items[0].port.?);
    try testing.expectEqualStrings("ipv4", list.items[0].family.?);
}

test "parse multiple addresses" {
    var list = try parse(testing.allocator, "unix:path=/a;tcp:host=h,port=1");
    defer list.deinit(testing.allocator);
    try testing.expectEqual(@as(usize, 2), list.items.len);
    try testing.expectEqual(Kind.unix, list.items[0].kind);
    try testing.expectEqual(Kind.tcp, list.items[1].kind);
}

test "unescape %XX in values" {
    var list = try parse(testing.allocator, "unix:path=%2Ftmp%2Fx");
    defer list.deinit(testing.allocator);
    try testing.expectEqualStrings("/tmp/x", list.items[0].path.?);
}

test "reject malformed addresses" {
    try testing.expectError(Error.InvalidAddress, parse(testing.allocator, "nocolon"));
    try testing.expectError(Error.UnknownTransport, parse(testing.allocator, "frob:path=/x"));
    try testing.expectError(Error.InvalidAddress, parse(testing.allocator, "unix:path")); // key without '='
    try testing.expectError(Error.InvalidPort, parse(testing.allocator, "tcp:host=h,port=notanumber"));
    try testing.expectError(Error.InvalidEscape, parse(testing.allocator, "unix:path=%zz"));
    try testing.expectError(Error.InvalidAddress, parse(testing.allocator, ""));
}
