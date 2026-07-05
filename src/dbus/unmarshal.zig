//! D-Bus unmarshaller: a bounds-checked `Reader` over a byte buffer, plus a
//! dynamic `Value` tree read from a signature. Strings point into the buffer;
//! only container payloads are heap-allocated.

const std = @import("std");
const types = @import("types.zig");
const signature = @import("signature.zig");

pub const Error = error{
    OutOfBounds,
    InvalidBoolean,
    InvalidString,
    InvalidSignature,
    DepthExceeded,
    ArrayTooLong,
} || std.mem.Allocator.Error;

/// Max container nesting depth when reading a dynamic value. Matches libdbus's
/// limit and bounds data-driven variant recursion (which the signature-level
/// depth cap cannot see).
pub const max_recursion_depth = 64;

/// D-Bus caps a single array's marshalled length at 64 MiB.
pub const max_array_len = 64 * 1024 * 1024;

/// A dynamically-typed D-Bus value read from a signature. String-like payloads
/// borrow from the Reader's buffer; array/struct/variant/dict_entry payloads are
/// heap-allocated and must be released with `freeValue`.
pub const Value = union(enum) {
    byte: u8,
    boolean: bool,
    int16: i16,
    uint16: u16,
    int32: i32,
    uint32: u32,
    int64: i64,
    uint64: u64,
    double: f64,
    unix_fd: u32,
    string: []const u8,
    object_path: []const u8,
    signature: []const u8,
    array: []Value,
    @"struct": []Value,
    variant: *Value,
    dict_entry: *[2]Value,
};

/// Recursively free everything `readValue` heap-allocated for `v`.
pub fn freeValue(gpa: std.mem.Allocator, v: Value) void {
    switch (v) {
        .array, .@"struct" => |items| {
            for (items) |item| freeValue(gpa, item);
            gpa.free(items);
        },
        .variant => |inner| {
            freeValue(gpa, inner.*);
            gpa.destroy(inner);
        },
        .dict_entry => |pair| {
            freeValue(gpa, pair[0]);
            freeValue(gpa, pair[1]);
            gpa.destroy(pair);
        },
        else => {},
    }
}

pub const Reader = struct {
    data: []const u8,
    pos: usize = 0,
    endian: std.builtin.Endian,

    pub fn init(data: []const u8, endian: std.builtin.Endian) Reader {
        return .{ .data = data, .endian = endian };
    }

    pub fn remaining(self: *Reader) usize {
        return self.data.len - self.pos;
    }

    /// Advance `pos` to the next multiple of `alignment`, verifying the padding
    /// bytes are present (their value is not checked).
    pub fn @"align"(self: *Reader, alignment: u8) Error!void {
        const rem = self.pos % alignment;
        if (rem == 0) return;
        const pad = alignment - rem;
        if (self.pos + pad > self.data.len) return Error.OutOfBounds;
        self.pos += pad;
    }

    fn take(self: *Reader, n: usize) Error![]const u8 {
        // Overflow-safe: pos <= data.len is an invariant, so the subtraction
        // never underflows and no attacker-controlled add can wrap.
        if (n > self.data.len - self.pos) return Error.OutOfBounds;
        const out = self.data[self.pos .. self.pos + n];
        self.pos += n;
        return out;
    }

    fn getInt(self: *Reader, comptime T: type) Error!T {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        try self.@"align"(n);
        const bytes = try self.take(n);
        return std.mem.readInt(T, bytes[0..n], self.endian);
    }

    pub fn byte(self: *Reader) Error!u8 {
        return (try self.take(1))[0];
    }
    pub fn boolean(self: *Reader) Error!bool {
        const v = try self.getInt(u32);
        return switch (v) {
            0 => false,
            1 => true,
            else => Error.InvalidBoolean,
        };
    }
    pub fn int16(self: *Reader) Error!i16 {
        return self.getInt(i16);
    }
    pub fn uint16(self: *Reader) Error!u16 {
        return self.getInt(u16);
    }
    pub fn int32(self: *Reader) Error!i32 {
        return self.getInt(i32);
    }
    pub fn uint32(self: *Reader) Error!u32 {
        return self.getInt(u32);
    }
    pub fn int64(self: *Reader) Error!i64 {
        return self.getInt(i64);
    }
    pub fn uint64(self: *Reader) Error!u64 {
        return self.getInt(u64);
    }
    pub fn double(self: *Reader) Error!f64 {
        return @bitCast(try self.getInt(u64));
    }
    pub fn unixFd(self: *Reader) Error!u32 {
        return self.getInt(u32);
    }

    pub fn string(self: *Reader) Error![]const u8 {
        const len = try self.getInt(u32);
        const s = try self.take(len);
        const nul = try self.take(1);
        if (nul[0] != 0) return Error.InvalidString;
        return s;
    }

    pub fn objectPath(self: *Reader) Error![]const u8 {
        return self.string();
    }

    pub fn signatureStr(self: *Reader) Error![]const u8 {
        const len = try self.byte();
        const s = try self.take(len);
        const nul = try self.take(1);
        if (nul[0] != 0) return Error.InvalidString;
        return s;
    }

    /// Read a single complete type given its `sig`, recursing into containers.
    /// Heap-allocates container payloads with `gpa` (free via `freeValue`).
    /// `sig` must be a single complete type (validated by the caller for
    /// top-level bodies; variant inner signatures are validated here).
    pub fn readValue(self: *Reader, gpa: std.mem.Allocator, sig: []const u8) Error!Value {
        return self.readValueDepth(gpa, sig, 0);
    }

    fn readValueDepth(self: *Reader, gpa: std.mem.Allocator, sig: []const u8, depth: usize) Error!Value {
        if (sig.len == 0) return Error.InvalidSignature;
        if (depth > max_recursion_depth) return Error.DepthExceeded;
        const t = types.fromCode(sig[0]) orelse return Error.InvalidSignature;
        switch (t) {
            .byte => return .{ .byte = try self.byte() },
            .boolean => return .{ .boolean = try self.boolean() },
            .int16 => return .{ .int16 = try self.int16() },
            .uint16 => return .{ .uint16 = try self.uint16() },
            .int32 => return .{ .int32 = try self.int32() },
            .uint32 => return .{ .uint32 = try self.uint32() },
            .int64 => return .{ .int64 = try self.int64() },
            .uint64 => return .{ .uint64 = try self.uint64() },
            .double => return .{ .double = try self.double() },
            .unix_fd => return .{ .unix_fd = try self.unixFd() },
            .string => return .{ .string = try self.string() },
            .object_path => return .{ .object_path = try self.objectPath() },
            .signature => return .{ .signature = try self.signatureStr() },
            .variant => {
                const inner_sig = try self.signatureStr();
                // A variant carries exactly one complete type; reject anything else.
                if (!signature.isSingleCompleteType(inner_sig)) return Error.InvalidSignature;
                const ptr = try gpa.create(Value);
                errdefer gpa.destroy(ptr);
                ptr.* = try self.readValueDepth(gpa, inner_sig, depth + 1);
                return .{ .variant = ptr };
            },
            .array => {
                const elem_len = signature.completeTypeLenInArray(sig[1..]) catch return Error.InvalidSignature;
                const elem_sig = sig[1 .. 1 + elem_len];
                const elem_type = types.fromCode(elem_sig[0]).?;
                const byte_len = try self.getInt(u32);
                if (byte_len > max_array_len) return Error.ArrayTooLong;
                try self.@"align"(types.alignmentOf(elem_type));
                if (byte_len > self.data.len - self.pos) return Error.OutOfBounds;
                const end = self.pos + byte_len;
                var list: std.ArrayList(Value) = .empty;
                errdefer {
                    for (list.items) |item| freeValue(gpa, item);
                    list.deinit(gpa);
                }
                while (self.pos < end) {
                    const item = try self.readValueDepth(gpa, elem_sig, depth + 1);
                    try list.append(gpa, item);
                }
                // An element that overran its declared span is malformed.
                if (self.pos != end) return Error.OutOfBounds;
                return .{ .array = try list.toOwnedSlice(gpa) };
            },
            .struct_begin => {
                try self.@"align"(8);
                var list: std.ArrayList(Value) = .empty;
                errdefer {
                    for (list.items) |item| freeValue(gpa, item);
                    list.deinit(gpa);
                }
                const inner = sig[1 .. sig.len - 1]; // strip '(' ')'
                var it = signature.Iterator.init(inner);
                while (it.next()) |field_sig| {
                    const item = try self.readValueDepth(gpa, field_sig, depth + 1);
                    try list.append(gpa, item);
                }
                return .{ .@"struct" = try list.toOwnedSlice(gpa) };
            },
            .dict_begin => {
                try self.@"align"(8);
                const pair = try gpa.create([2]Value);
                errdefer gpa.destroy(pair);
                const key_sig = sig[1..2];
                const val_sig = sig[2 .. sig.len - 1];
                pair[0] = try self.readValueDepth(gpa, key_sig, depth + 1);
                errdefer freeValue(gpa, pair[0]);
                pair[1] = try self.readValueDepth(gpa, val_sig, depth + 1);
                return .{ .dict_entry = pair };
            },
            .struct_end, .dict_end => return Error.InvalidSignature,
        }
    }
};

const testing = std.testing;
const marshal = @import("marshal.zig");

test "read fixed integers little-endian with alignment" {
    const data = &[_]u8{ 0x05, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde };
    var r = Reader.init(data, .little);
    try testing.expectEqual(@as(u8, 0x05), try r.byte());
    try testing.expectEqual(@as(u32, 0xdeadbeef), try r.uint32());
    try testing.expectEqual(@as(usize, 0), r.remaining());
}

test "read string" {
    const data = &[_]u8{ 0x03, 0x00, 0x00, 0x00, 'f', 'o', 'o', 0x00 };
    var r = Reader.init(data, .little);
    try testing.expectEqualStrings("foo", try r.string());
}

test "read signature" {
    const data = &[_]u8{ 0x05, 'a', '{', 's', 'v', '}', 0x00 };
    var r = Reader.init(data, .little);
    try testing.expectEqualStrings("a{sv}", try r.signatureStr());
}

test "out of bounds is caught" {
    const data = &[_]u8{ 0x01, 0x00 };
    var r = Reader.init(data, .little);
    try testing.expectError(Error.OutOfBounds, r.uint32());
}

test "invalid boolean rejected" {
    const data = &[_]u8{ 0x02, 0x00, 0x00, 0x00 };
    var r = Reader.init(data, .little);
    try testing.expectError(Error.InvalidBoolean, r.boolean());
}

test "readValue: array of u32" {
    const data = &[_]u8{
        0x08, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
    };
    var r = Reader.init(data, .little);
    const v = try r.readValue(testing.allocator, "au");
    defer freeValue(testing.allocator, v);
    try testing.expectEqual(@as(usize, 2), v.array.len);
    try testing.expectEqual(@as(u32, 1), v.array[0].uint32);
    try testing.expectEqual(@as(u32, 2), v.array[1].uint32);
}

test "readValue: variant of u32" {
    const data = &[_]u8{ 0x01, 'u', 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00 };
    var r = Reader.init(data, .little);
    const v = try r.readValue(testing.allocator, "v");
    defer freeValue(testing.allocator, v);
    try testing.expectEqual(@as(u32, 0x2a), v.variant.uint32);
}

test "readValue: struct (us)" {
    const data = &[_]u8{
        0x07, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
        'h',  'i',  0x00,
    };
    var r = Reader.init(data, .little);
    const v = try r.readValue(testing.allocator, "(us)");
    defer freeValue(testing.allocator, v);
    try testing.expectEqual(@as(u32, 7), v.@"struct"[0].uint32);
    try testing.expectEqualStrings("hi", v.@"struct"[1].string);
}

test "readValue: empty variant signature rejected" {
    const data = &[_]u8{ 0x00, 0x00 }; // sig length 0, NUL
    var r = Reader.init(data, .little);
    try testing.expectError(Error.InvalidSignature, r.readValue(testing.allocator, "v"));
}

test "readValue: non-single-type variant signature rejected" {
    // inner sig "ii" is two types, not one.
    const data = &[_]u8{ 0x02, 'i', 'i', 0x00 };
    var r = Reader.init(data, .little);
    try testing.expectError(Error.InvalidSignature, r.readValue(testing.allocator, "v"));
}

test "readValue: variant nesting depth is bounded" {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var w = marshal.Writer.init(testing.allocator, &buf, .little);
    var i: usize = 0;
    while (i < 70) : (i += 1) try w.beginVariant("v");
    try w.beginVariant("y");
    try w.byte(1);

    var r = Reader.init(buf.items, .little);
    try testing.expectError(Error.DepthExceeded, r.readValue(testing.allocator, "v"));
}

test "readValue: oversized array length rejected" {
    const data = &[_]u8{ 0xFF, 0xFF, 0xFF, 0xFF };
    var r = Reader.init(data, .little);
    try testing.expectError(Error.ArrayTooLong, r.readValue(testing.allocator, "au"));
}

test "readValue: array element overrun rejected" {
    // Declares 2 element bytes but a u32 element consumes 4, overrunning the span.
    const data = &[_]u8{ 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 };
    var r = Reader.init(data, .little);
    try testing.expectError(Error.OutOfBounds, r.readValue(testing.allocator, "au"));
}

test "round-trip struct both endians" {
    for ([_]std.builtin.Endian{ .little, .big }) |endian| {
        var buf: std.ArrayList(u8) = .empty;
        defer buf.deinit(testing.allocator);
        var w = marshal.Writer.init(testing.allocator, &buf, endian);

        try w.beginStruct();
        try w.uint32(42);
        try w.string("hi");
        const actx = try w.beginArray(4);
        try w.uint32(1);
        try w.uint32(2);
        try w.uint32(3);
        w.endArray(actx);

        var r = Reader.init(buf.items, endian);
        const v = try r.readValue(testing.allocator, "(usau)");
        defer freeValue(testing.allocator, v);
        try testing.expectEqual(@as(u32, 42), v.@"struct"[0].uint32);
        try testing.expectEqualStrings("hi", v.@"struct"[1].string);
        try testing.expectEqual(@as(usize, 3), v.@"struct"[2].array.len);
        try testing.expectEqual(@as(u32, 3), v.@"struct"[2].array[2].uint32);
        try testing.expectEqual(@as(usize, 0), r.remaining());
    }
}
