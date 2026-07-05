//! D-Bus message (de)serialization. The header is itself the D-Bus struct
//! `yyyyuua(yv)` (endianness, type, flags, version, body length, serial, and the
//! header-field array), padded to 8 bytes before the body.

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const signature = @import("signature.zig");
const marshal = @import("marshal.zig");
const unmarshal = @import("unmarshal.zig");

const native_endian = builtin.cpu.arch.endian();

pub const MessageType = enum(u8) {
    method_call = 1,
    method_return = 2,
    error_ = 3,
    signal = 4,
};

pub const Flags = packed struct(u8) {
    no_reply_expected: bool = false,
    no_auto_start: bool = false,
    allow_interactive_authorization: bool = false,
    _pad: u5 = 0,
};

pub const HeaderField = enum(u8) {
    path = 1,
    interface = 2,
    member = 3,
    error_name = 4,
    reply_serial = 5,
    destination = 6,
    sender = 7,
    signature = 8,
    unix_fds = 9,
};

pub const protocol_version = 1;

/// D-Bus caps a whole message (header + body) at 128 MiB.
pub const max_message_len = 128 * 1024 * 1024;

pub const Error = error{
    MissingRequiredField,
    InvalidEndianness,
    InvalidMessageType,
    BodyLengthMismatch,
    UnsupportedProtocolVersion,
    InvalidHeaderField,
    MessageTooLong,
} || marshal.Writer.Error || unmarshal.Error;

/// The variant signature each header field must carry.
fn fieldSignature(field: HeaderField) []const u8 {
    return switch (field) {
        .path => "o",
        .interface, .member, .error_name, .destination, .sender => "s",
        .signature => "g",
        .reply_serial, .unix_fds => "u",
    };
}

/// Total on-wire length of the message whose first bytes are `prefix`, or null
/// if fewer than 16 bytes are available (the minimum to read both length fields)
/// or the endianness byte is invalid. Lets a connection frame a stream without
/// fully parsing each message. Layout: body length at [4..8], header-fields array
/// length at [12..16], both in the message's endianness; the header is padded to
/// 8 before the body.
pub fn wireLength(prefix: []const u8) ?usize {
    if (prefix.len < 16) return null;
    const endian: std.builtin.Endian = switch (prefix[0]) {
        'l' => .little,
        'B' => .big,
        else => return null,
    };
    const body_len = std.mem.readInt(u32, prefix[4..8], endian);
    const fields_len = std.mem.readInt(u32, prefix[12..16], endian);
    const header_len = std.mem.alignForward(usize, 16 + @as(usize, fields_len), 8);
    return header_len + body_len;
}

pub const Message = struct {
    msg_type: MessageType,
    flags: Flags = .{},
    serial: u32,
    path: ?[]const u8 = null,
    interface: ?[]const u8 = null,
    member: ?[]const u8 = null,
    error_name: ?[]const u8 = null,
    reply_serial: ?u32 = null,
    destination: ?[]const u8 = null,
    sender: ?[]const u8 = null,
    body_signature: ?[]const u8 = null,
    unix_fds: ?u32 = null,
    body: []const u8 = &.{},
    /// Endianness the message was received in; set by `deserialize`, used to read
    /// the body. Ignored by `serialize` (which takes an explicit endian).
    endian: std.builtin.Endian = native_endian,

    fn checkRequired(self: Message) Error!void {
        switch (self.msg_type) {
            .method_call => if (self.path == null or self.member == null) return Error.MissingRequiredField,
            .signal => if (self.path == null or self.interface == null or self.member == null) return Error.MissingRequiredField,
            .method_return => if (self.reply_serial == null) return Error.MissingRequiredField,
            .error_ => if (self.error_name == null or self.reply_serial == null) return Error.MissingRequiredField,
        }
        if (self.body.len > 0 and self.body_signature == null) return Error.MissingRequiredField;
    }

    pub fn serialize(self: Message, gpa: std.mem.Allocator, buf: *std.ArrayList(u8), endian: std.builtin.Endian) Error!void {
        try self.checkRequired();
        var w = marshal.Writer.init(gpa, buf, endian);

        try w.byte(switch (endian) {
            .little => 'l',
            .big => 'B',
        });
        try w.byte(@intFromEnum(self.msg_type));
        try w.byte(@as(u8, @bitCast(self.flags)));
        try w.byte(protocol_version);
        try w.uint32(@intCast(self.body.len));
        try w.uint32(self.serial);

        const actx = try w.beginArray(8); // a(yv): struct element alignment 8
        try writeStrField(&w, .path, self.path);
        try writeStrField(&w, .interface, self.interface);
        try writeStrField(&w, .member, self.member);
        try writeStrField(&w, .error_name, self.error_name);
        try writeU32Field(&w, .reply_serial, self.reply_serial);
        try writeStrField(&w, .destination, self.destination);
        try writeStrField(&w, .sender, self.sender);
        try writeSigField(&w, .signature, self.body_signature);
        try writeU32Field(&w, .unix_fds, self.unix_fds);
        w.endArray(actx);

        try w.pad(8);
        try buf.appendSlice(gpa, self.body);
    }

    fn writeStrField(w: *marshal.Writer, field: HeaderField, val: ?[]const u8) Error!void {
        const s = val orelse return;
        try w.beginStruct();
        try w.byte(@intFromEnum(field));
        const sig: []const u8 = if (field == .path) "o" else "s";
        try w.beginVariant(sig);
        try w.string(s);
    }

    fn writeSigField(w: *marshal.Writer, field: HeaderField, val: ?[]const u8) Error!void {
        const s = val orelse return;
        try w.beginStruct();
        try w.byte(@intFromEnum(field));
        try w.beginVariant("g");
        try w.signatureStr(s);
    }

    fn writeU32Field(w: *marshal.Writer, field: HeaderField, val: ?u32) Error!void {
        const n = val orelse return;
        try w.beginStruct();
        try w.byte(@intFromEnum(field));
        try w.beginVariant("u");
        try w.uint32(n);
    }

    pub fn deserialize(gpa: std.mem.Allocator, data: []const u8) Error!Message {
        if (data.len < 16) return unmarshal.Error.OutOfBounds;
        const endian: std.builtin.Endian = switch (data[0]) {
            'l' => .little,
            'B' => .big,
            else => return Error.InvalidEndianness,
        };
        var r = unmarshal.Reader.init(data, endian);
        _ = try r.byte(); // endianness
        const mt_raw = try r.byte();
        const mt = std.enums.fromInt(MessageType, mt_raw) orelse return Error.InvalidMessageType;
        const flags: Flags = @bitCast(try r.byte());
        const version = try r.byte();
        if (version != protocol_version) return Error.UnsupportedProtocolVersion;
        const body_len = try r.uint32();
        if (body_len > max_message_len) return Error.MessageTooLong;
        const serial = try r.uint32();

        var msg = Message{ .msg_type = mt, .flags = flags, .serial = serial, .endian = endian };

        const arr_len = try r.uint32();
        try r.@"align"(8);
        if (arr_len > data.len - r.pos) return unmarshal.Error.OutOfBounds;
        const fields_end = r.pos + arr_len;
        while (r.pos < fields_end) {
            try r.@"align"(8);
            const code = try r.byte();
            const vsig = try r.signatureStr();
            const field = std.enums.fromInt(HeaderField, code) orelse {
                // Unknown field: skip its value by reading and discarding.
                const v = try r.readValue(gpa, vsig);
                unmarshal.freeValue(gpa, v);
                continue;
            };
            // Each known field must carry its spec-mandated variant signature.
            if (!std.mem.eql(u8, vsig, fieldSignature(field))) return Error.InvalidHeaderField;
            switch (field) {
                .path => msg.path = try r.string(),
                .interface => msg.interface = try r.string(),
                .member => msg.member = try r.string(),
                .error_name => msg.error_name = try r.string(),
                .destination => msg.destination = try r.string(),
                .sender => msg.sender = try r.string(),
                .signature => msg.body_signature = try r.signatureStr(),
                .reply_serial => msg.reply_serial = try r.uint32(),
                .unix_fds => msg.unix_fds = try r.uint32(),
            }
        }
        // The field array must be consumed exactly.
        if (r.pos != fields_end) return unmarshal.Error.OutOfBounds;
        try r.@"align"(8);
        if (body_len > data.len - r.pos) return Error.BodyLengthMismatch;
        msg.body = data[r.pos .. r.pos + body_len];
        try msg.checkRequired();
        return msg;
    }
};

const testing = std.testing;

test "serialize/deserialize a method call round-trips" {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(testing.allocator);
    var bw = marshal.Writer.init(testing.allocator, &body, .little);
    try bw.string("hello world");

    const msg = Message{
        .msg_type = .method_call,
        .serial = 1,
        .path = "/org/freedesktop/DBus",
        .interface = "org.freedesktop.DBus",
        .member = "Hello",
        .destination = "org.freedesktop.DBus",
        .body_signature = "s",
        .body = body.items,
    };

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try msg.serialize(testing.allocator, &buf, .little);

    try testing.expectEqual(@as(usize, 0), (buf.items.len - body.items.len) % 8);

    const got = try Message.deserialize(testing.allocator, buf.items);
    try testing.expectEqual(MessageType.method_call, got.msg_type);
    try testing.expectEqual(@as(u32, 1), got.serial);
    try testing.expectEqualStrings("/org/freedesktop/DBus", got.path.?);
    try testing.expectEqualStrings("Hello", got.member.?);
    try testing.expectEqualStrings("org.freedesktop.DBus", got.destination.?);
    try testing.expectEqualStrings("s", got.body_signature.?);
    try testing.expectEqualSlices(u8, body.items, got.body);
}

test "wireLength frames a serialized message" {
    const msg = Message{ .msg_type = .signal, .serial = 1, .path = "/a", .interface = "a.b", .member = "M" };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try msg.serialize(testing.allocator, &buf, .little);
    try testing.expect(wireLength(buf.items[0..8]) == null); // not enough bytes
    try testing.expectEqual(@as(?usize, buf.items.len), wireLength(buf.items));
}

test "serialize/deserialize round-trips big-endian" {
    const msg = Message{
        .msg_type = .signal,
        .serial = 0x01020304,
        .path = "/org/example",
        .interface = "org.example.Iface",
        .member = "Ping",
    };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try msg.serialize(testing.allocator, &buf, .big);

    // Fixed-header byte anchors: endianness 'B', type SIGNAL(4), version 1.
    try testing.expectEqual(@as(u8, 'B'), buf.items[0]);
    try testing.expectEqual(@as(u8, @intFromEnum(MessageType.signal)), buf.items[1]);
    try testing.expectEqual(@as(u8, protocol_version), buf.items[3]);
    // Serial is a big-endian u32 at offset 8.
    try testing.expectEqual(@as(u32, 0x01020304), std.mem.readInt(u32, buf.items[8..12], .big));

    const got = try Message.deserialize(testing.allocator, buf.items);
    try testing.expectEqual(@as(u32, 0x01020304), got.serial);
    try testing.expectEqualStrings("/org/example", got.path.?);
    try testing.expectEqualStrings("org.example.Iface", got.interface.?);
    try testing.expectEqualStrings("Ping", got.member.?);
}

test "serialize rejects a method call missing PATH" {
    const msg = Message{ .msg_type = .method_call, .serial = 1, .member = "Hello" };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try testing.expectError(Error.MissingRequiredField, msg.serialize(testing.allocator, &buf, .little));
}

test "deserialize enforces required fields" {
    // Build a valid SIGNAL, then flip its type byte to METHOD_RETURN(2), which
    // requires REPLY_SERIAL. That field is absent, so the read must reject it.
    const msg = Message{ .msg_type = .signal, .serial = 3, .path = "/a", .interface = "a.b", .member = "M" };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try msg.serialize(testing.allocator, &buf, .little);
    buf.items[1] = @intFromEnum(MessageType.method_return);
    try testing.expectError(Error.MissingRequiredField, Message.deserialize(testing.allocator, buf.items));
}

test "deserialize rejects an unsupported protocol version" {
    const msg = Message{ .msg_type = .signal, .serial = 1, .path = "/a", .interface = "a.b", .member = "M" };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try msg.serialize(testing.allocator, &buf, .little);
    buf.items[3] = 2; // protocol version byte
    try testing.expectError(Error.UnsupportedProtocolVersion, Message.deserialize(testing.allocator, buf.items));
}

test "deserialize rejects a wrong header-field variant signature" {
    const msg = Message{ .msg_type = .signal, .serial = 1, .path = "/a", .interface = "a.b", .member = "M" };
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    try msg.serialize(testing.allocator, &buf, .little);
    // The first header field is PATH(1) with variant sig "o". Corrupt the sig
    // byte from 'o' to 's'; the field-signature check must reject it.
    const idx = std.mem.indexOfScalar(u8, buf.items, 'o').?;
    buf.items[idx] = 's';
    try testing.expectError(Error.InvalidHeaderField, Message.deserialize(testing.allocator, buf.items));
}
