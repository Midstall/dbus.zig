//! D-Bus marshaller: a streaming `Writer` that appends values to a byte buffer
//! with correct D-Bus alignment and the caller-chosen endianness.

const std = @import("std");
const types = @import("types.zig");

/// Bookkeeping returned by `beginArray` and consumed by `endArray` to backpatch
/// the array's byte-length prefix once its elements are written.
pub const ArrayCtx = struct {
    len_pos: usize,
    data_start: usize,
};

pub const Writer = struct {
    gpa: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    endian: std.builtin.Endian,

    pub const Error = std.mem.Allocator.Error || error{ValueTooLong};

    pub fn init(gpa: std.mem.Allocator, buf: *std.ArrayList(u8), endian: std.builtin.Endian) Writer {
        return .{ .gpa = gpa, .buf = buf, .endian = endian };
    }

    /// Append zero bytes until the buffer length is a multiple of `alignment`.
    pub fn pad(self: *Writer, alignment: u8) Error!void {
        const rem = self.buf.items.len % alignment;
        if (rem == 0) return;
        try self.buf.appendNTimes(self.gpa, 0, alignment - rem);
    }

    fn putInt(self: *Writer, comptime T: type, v: T) Error!void {
        const n = @divExact(@typeInfo(T).int.bits, 8);
        try self.pad(n);
        var tmp: [n]u8 = undefined;
        std.mem.writeInt(T, &tmp, v, self.endian);
        try self.buf.appendSlice(self.gpa, &tmp);
    }

    pub fn byte(self: *Writer, v: u8) Error!void {
        try self.buf.append(self.gpa, v);
    }
    pub fn boolean(self: *Writer, v: bool) Error!void {
        try self.putInt(u32, @intFromBool(v));
    }
    pub fn int16(self: *Writer, v: i16) Error!void {
        try self.putInt(i16, v);
    }
    pub fn uint16(self: *Writer, v: u16) Error!void {
        try self.putInt(u16, v);
    }
    pub fn int32(self: *Writer, v: i32) Error!void {
        try self.putInt(i32, v);
    }
    pub fn uint32(self: *Writer, v: u32) Error!void {
        try self.putInt(u32, v);
    }
    pub fn int64(self: *Writer, v: i64) Error!void {
        try self.putInt(i64, v);
    }
    pub fn uint64(self: *Writer, v: u64) Error!void {
        try self.putInt(u64, v);
    }
    pub fn double(self: *Writer, v: f64) Error!void {
        try self.putInt(u64, @bitCast(v));
    }
    pub fn unixFd(self: *Writer, index: u32) Error!void {
        try self.putInt(u32, index);
    }

    /// STRING wire form: u32 length (excludes the NUL), the bytes, then a NUL.
    pub fn string(self: *Writer, s: []const u8) Error!void {
        if (s.len > std.math.maxInt(u32)) return error.ValueTooLong;
        try self.putInt(u32, @intCast(s.len));
        try self.buf.appendSlice(self.gpa, s);
        try self.buf.append(self.gpa, 0);
    }

    /// OBJECT_PATH has the same wire form as STRING.
    pub fn objectPath(self: *Writer, s: []const u8) Error!void {
        try self.string(s);
    }

    /// SIGNATURE wire form: u8 length (excludes the NUL), the bytes, then a NUL.
    pub fn signatureStr(self: *Writer, s: []const u8) Error!void {
        if (s.len > 255) return error.ValueTooLong;
        try self.buf.append(self.gpa, @intCast(s.len));
        try self.buf.appendSlice(self.gpa, s);
        try self.buf.append(self.gpa, 0);
    }

    /// Align to 8 for a STRUCT or DICT_ENTRY. The fields follow directly.
    pub fn beginStruct(self: *Writer) Error!void {
        try self.pad(8);
    }

    /// Begin an ARRAY: reserve the u32 byte-length prefix (aligned 4), then pad
    /// to the element alignment. The returned context records where the element
    /// data starts so `endArray` can backpatch the length.
    pub fn beginArray(self: *Writer, elem_align: u8) Error!ArrayCtx {
        try self.pad(4);
        const len_pos = self.buf.items.len;
        try self.buf.appendNTimes(self.gpa, 0, 4); // length placeholder
        try self.pad(elem_align);
        return .{ .len_pos = len_pos, .data_start = self.buf.items.len };
    }

    /// Backpatch the array length prefix with the number of element bytes
    /// written since `beginArray` (post-length padding is excluded).
    pub fn endArray(self: *Writer, ctx: ArrayCtx) void {
        const len: u32 = @intCast(self.buf.items.len - ctx.data_start);
        std.mem.writeInt(u32, self.buf.items[ctx.len_pos..][0..4], len, self.endian);
    }

    /// Begin a VARIANT: write its signature. The caller then marshals exactly
    /// one value of that type.
    pub fn beginVariant(self: *Writer, sig: []const u8) Error!void {
        try self.signatureStr(sig);
    }
};

const testing = std.testing;

fn expectBytes(expected: []const u8, endian: std.builtin.Endian, comptime f: anytype) !void {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(testing.allocator);
    var w = Writer.init(testing.allocator, &buf, endian);
    try f(&w);
    try testing.expectEqualSlices(u8, expected, buf.items);
}

test "fixed integers little-endian" {
    try expectBytes(&.{0x2a}, .little, struct {
        fn f(w: *Writer) !void {
            try w.byte(0x2a);
        }
    }.f);
    try expectBytes(&.{ 0x78, 0x56, 0x34, 0x12 }, .little, struct {
        fn f(w: *Writer) !void {
            try w.uint32(0x12345678);
        }
    }.f);
    try expectBytes(&.{ 0x01, 0x00, 0x00, 0x00 }, .little, struct {
        fn f(w: *Writer) !void {
            try w.boolean(true);
        }
    }.f);
}

test "alignment padding before a u32 after a byte" {
    try expectBytes(&.{ 0x05, 0x00, 0x00, 0x00, 0xef, 0xbe, 0xad, 0xde }, .little, struct {
        fn f(w: *Writer) !void {
            try w.byte(0x05);
            try w.uint32(0xdeadbeef);
        }
    }.f);
}

test "u64 big-endian aligns to 8" {
    try expectBytes(&.{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 }, .big, struct {
        fn f(w: *Writer) !void {
            try w.uint64(1);
            try w.uint64(2);
        }
    }.f);
}

test "string wire form" {
    try expectBytes(&.{ 0x03, 0x00, 0x00, 0x00, 'f', 'o', 'o', 0x00 }, .little, struct {
        fn f(w: *Writer) !void {
            try w.string("foo");
        }
    }.f);
}

test "signature wire form" {
    try expectBytes(&.{ 0x05, 'a', '{', 's', 'v', '}', 0x00 }, .little, struct {
        fn f(w: *Writer) !void {
            try w.signatureStr("a{sv}");
        }
    }.f);
}

test "string aligns to 4 after a byte" {
    try expectBytes(&.{ 0xaa, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 'x', 0x00 }, .little, struct {
        fn f(w: *Writer) !void {
            try w.byte(0xaa);
            try w.string("x");
        }
    }.f);
}

test "array of two u32" {
    try expectBytes(&.{
        0x08, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00,
    }, .little, struct {
        fn f(w: *Writer) !void {
            const ctx = try w.beginArray(types.alignmentOf(.uint32));
            try w.uint32(1);
            try w.uint32(2);
            w.endArray(ctx);
        }
    }.f);
}

test "empty array of u64 still pads element start to 8" {
    try expectBytes(&.{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, .little, struct {
        fn f(w: *Writer) !void {
            const ctx = try w.beginArray(types.alignmentOf(.uint64));
            w.endArray(ctx);
        }
    }.f);
}

test "variant holding a u32" {
    try expectBytes(&.{ 0x01, 'u', 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00 }, .little, struct {
        fn f(w: *Writer) !void {
            try w.beginVariant("u");
            try w.uint32(0x2a);
        }
    }.f);
}

test "struct aligns to 8" {
    try expectBytes(&.{ 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00 }, .little, struct {
        fn f(w: *Writer) !void {
            try w.byte(0xaa);
            try w.beginStruct();
            try w.uint32(1);
        }
    }.f);
}
