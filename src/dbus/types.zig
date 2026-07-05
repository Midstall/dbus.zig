//! D-Bus type system: the single-character type codes, their wire alignments,
//! and predicates for classifying them (basic / fixed / string-like).

const std = @import("std");

pub const Type = enum(u8) {
    byte = 'y',
    boolean = 'b',
    int16 = 'n',
    uint16 = 'q',
    int32 = 'i',
    uint32 = 'u',
    int64 = 'x',
    uint64 = 't',
    double = 'd',
    unix_fd = 'h',
    string = 's',
    object_path = 'o',
    signature = 'g',
    array = 'a',
    variant = 'v',
    struct_begin = '(',
    struct_end = ')',
    dict_begin = '{',
    dict_end = '}',
};

/// Map a raw signature byte to a `Type`, or null if it is not a valid code.
pub fn fromCode(c: u8) ?Type {
    return switch (c) {
        'y', 'b', 'n', 'q', 'i', 'u', 'x', 't', 'd', 'h', 's', 'o', 'g', 'a', 'v', '(', ')', '{', '}' => @enumFromInt(c),
        else => null,
    };
}

/// Wire alignment of a type in bytes. Containers align by their opening token
/// (struct and dict-entry both align to 8).
pub fn alignmentOf(t: Type) u8 {
    return switch (t) {
        .byte, .signature, .variant => 1,
        .int16, .uint16 => 2,
        .boolean, .int32, .uint32, .unix_fd, .string, .object_path, .array => 4,
        .int64, .uint64, .double, .struct_begin, .dict_begin => 8,
        .struct_end, .dict_end => 1,
    };
}

/// Fixed-size types marshal to a constant number of bytes.
pub fn isFixed(t: Type) bool {
    return switch (t) {
        .byte, .boolean, .int16, .uint16, .int32, .uint32, .int64, .uint64, .double, .unix_fd => true,
        else => false,
    };
}

/// String, object path, and signature share length-prefixed wire encodings.
pub fn isStringLike(t: Type) bool {
    return switch (t) {
        .string, .object_path, .signature => true,
        else => false,
    };
}

/// Basic types are anything that is not a container (array/variant/struct/dict).
pub fn isBasic(t: Type) bool {
    return isFixed(t) or isStringLike(t);
}

const testing = std.testing;

test "alignmentOf matches the D-Bus spec" {
    try testing.expectEqual(@as(u8, 1), alignmentOf(.byte));
    try testing.expectEqual(@as(u8, 1), alignmentOf(.signature));
    try testing.expectEqual(@as(u8, 1), alignmentOf(.variant));
    try testing.expectEqual(@as(u8, 2), alignmentOf(.int16));
    try testing.expectEqual(@as(u8, 2), alignmentOf(.uint16));
    try testing.expectEqual(@as(u8, 4), alignmentOf(.boolean));
    try testing.expectEqual(@as(u8, 4), alignmentOf(.uint32));
    try testing.expectEqual(@as(u8, 4), alignmentOf(.unix_fd));
    try testing.expectEqual(@as(u8, 4), alignmentOf(.string));
    try testing.expectEqual(@as(u8, 4), alignmentOf(.object_path));
    try testing.expectEqual(@as(u8, 4), alignmentOf(.array));
    try testing.expectEqual(@as(u8, 8), alignmentOf(.uint64));
    try testing.expectEqual(@as(u8, 8), alignmentOf(.double));
    try testing.expectEqual(@as(u8, 8), alignmentOf(.struct_begin));
    try testing.expectEqual(@as(u8, 8), alignmentOf(.dict_begin));
}

test "fromCode and predicates" {
    try testing.expectEqual(Type.uint32, fromCode('u').?);
    try testing.expect(fromCode('Q') == null);
    try testing.expect(isBasic(.string));
    try testing.expect(!isBasic(.array));
    try testing.expect(isFixed(.double));
    try testing.expect(!isFixed(.string));
    try testing.expect(isStringLike(.object_path));
}
