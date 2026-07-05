//! D-Bus signature parsing: validation, single-complete-type measurement, and
//! iteration over the top-level complete types of a signature string.

const std = @import("std");
const types = @import("types.zig");
const Type = types.Type;

pub const Error = error{
    InvalidSignature,
    SignatureTooLong,
    ExceededMaxDepth,
    InvalidDictEntry,
};

pub const max_len = 255;
pub const max_depth = 32;

/// Length of the single complete type starting at sig[0]. Recurses into
/// containers. Enforces nesting-depth limits and dict-entry structure.
pub fn completeTypeLen(sig: []const u8) Error!usize {
    return completeTypeLenDepth(sig, 0, 0);
}

fn completeTypeLenDepth(sig: []const u8, array_depth: usize, struct_depth: usize) Error!usize {
    if (sig.len == 0) return Error.InvalidSignature;
    const t = types.fromCode(sig[0]) orelse return Error.InvalidSignature;
    switch (t) {
        .array => {
            if (array_depth + 1 > max_depth) return Error.ExceededMaxDepth;
            const inner = try completeTypeLenDepth(sig[1..], array_depth + 1, struct_depth);
            return 1 + inner;
        },
        .struct_begin => {
            if (struct_depth + 1 > max_depth) return Error.ExceededMaxDepth;
            var i: usize = 1;
            var count: usize = 0;
            while (i < sig.len and sig[i] != @intFromEnum(Type.struct_end)) {
                i += try completeTypeLenDepth(sig[i..], array_depth, struct_depth + 1);
                count += 1;
            }
            if (i >= sig.len) return Error.InvalidSignature; // no closing ')'
            if (count == 0) return Error.InvalidSignature; // empty struct
            return i + 1; // include ')'
        },
        .dict_begin => {
            // Only valid as the immediate element type of an array.
            if (array_depth == 0) return Error.InvalidDictEntry;
            // Need a key byte at [1] and a value byte at [2] before indexing them.
            if (sig.len < 3) return Error.InvalidDictEntry;
            const key = types.fromCode(sig[1]) orelse return Error.InvalidDictEntry;
            if (!types.isBasic(key)) return Error.InvalidDictEntry;
            // A dict-entry must have exactly one value type; reject a missing one.
            if (sig[2] == @intFromEnum(Type.dict_end)) return Error.InvalidDictEntry;
            const val_len = try completeTypeLenDepth(sig[2..], array_depth, struct_depth + 1);
            const close = 2 + val_len;
            if (close >= sig.len or sig[close] != @intFromEnum(Type.dict_end)) return Error.InvalidDictEntry;
            return close + 1; // include '}'
        },
        .struct_end, .dict_end => return Error.InvalidSignature,
        else => return 1, // basic types and variant
    }
}

/// Length of a complete type that appears as an array element (so a leading
/// dict-entry `{...}` is measured in its valid array context).
pub fn completeTypeLenInArray(sig: []const u8) Error!usize {
    return completeTypeLenDepth(sig, 1, 0);
}

/// Validate a full signature (a concatenation of zero or more complete types).
pub fn validate(sig: []const u8) Error!void {
    if (sig.len > max_len) return Error.SignatureTooLong;
    var i: usize = 0;
    while (i < sig.len) {
        i += try completeTypeLen(sig[i..]);
    }
}

/// True if `sig` is exactly one complete type with no trailing bytes. Used to
/// validate variant inner signatures and header-field variant signatures, which
/// must each hold a single type.
pub fn isSingleCompleteType(sig: []const u8) bool {
    const len = completeTypeLen(sig) catch return false;
    return len == sig.len;
}

/// Yields each top-level complete-type slice of a signature. Assumes `sig` has
/// already been validated (a malformed type ends iteration).
pub const Iterator = struct {
    sig: []const u8,
    i: usize = 0,

    pub fn init(sig: []const u8) Iterator {
        return .{ .sig = sig };
    }

    pub fn next(self: *Iterator) ?[]const u8 {
        if (self.i >= self.sig.len) return null;
        const len = completeTypeLen(self.sig[self.i..]) catch return null;
        const out = self.sig[self.i .. self.i + len];
        self.i += len;
        return out;
    }
};

const testing = std.testing;

test "completeTypeLen" {
    try testing.expectEqual(@as(usize, 1), try completeTypeLen("i"));
    try testing.expectEqual(@as(usize, 2), try completeTypeLen("ai"));
    try testing.expectEqual(@as(usize, 5), try completeTypeLen("a{sv}"));
    try testing.expectEqual(@as(usize, 5), try completeTypeLen("(iis)x"));
    try testing.expectEqual(@as(usize, 1), try completeTypeLen("v"));
}

test "validate accepts good signatures" {
    try validate("");
    try validate("i");
    try validate("a{sv}");
    try validate("(i(ii)s)");
    try validate("aaai");
    try validate("h");
}

test "validate rejects bad signatures" {
    try testing.expectError(Error.InvalidSignature, validate("("));
    try testing.expectError(Error.InvalidSignature, validate(")"));
    try testing.expectError(Error.InvalidSignature, validate("a"));
    try testing.expectError(Error.InvalidSignature, validate("Q"));
    try testing.expectError(Error.InvalidDictEntry, validate("{sv}")); // dict-entry not inside array
    try testing.expectError(Error.InvalidDictEntry, validate("a{vs}")); // non-basic key
    try testing.expectError(Error.InvalidDictEntry, validate("a{s}")); // wrong element count
    try testing.expectError(Error.InvalidDictEntry, validate("a{s")); // truncated dict-entry (no OOB)
    try testing.expectError(Error.InvalidDictEntry, validate("a{")); // truncated dict-entry (no OOB)
}

test "isSingleCompleteType" {
    try testing.expect(isSingleCompleteType("i"));
    try testing.expect(isSingleCompleteType("a{sv}"));
    try testing.expect(!isSingleCompleteType("")); // empty
    try testing.expect(!isSingleCompleteType("ii")); // two types
    try testing.expect(!isSingleCompleteType("{sv}")); // dict outside array
}

test "Iterator yields top-level complete types" {
    var it = Iterator.init("ia{sv}(ii)");
    try testing.expectEqualStrings("i", it.next().?);
    try testing.expectEqualStrings("a{sv}", it.next().?);
    try testing.expectEqualStrings("(ii)", it.next().?);
    try testing.expect(it.next() == null);
}
