//! The bus name registry: unique names (`:1.N`) and well-known name ownership
//! with the RequestName queue semantics (allow-replacement / replace-existing /
//! do-not-queue). Connections are identified by an opaque `ConnId`; the daemon
//! maps those to unique names for NameOwnerChanged signals.

const std = @import("std");

pub const ConnId = u32;

pub const RequestFlags = packed struct(u32) {
    allow_replacement: bool = false,
    replace_existing: bool = false,
    do_not_queue: bool = false,
    _pad: u29 = 0,
};

pub const RequestResult = enum(u32) {
    primary_owner = 1,
    in_queue = 2,
    exists = 3,
    already_owner = 4,
};

pub const ReleaseResult = enum(u32) {
    released = 1,
    non_existent = 2,
    not_owner = 3,
};

/// The result of a request/release plus any resulting primary-owner change,
/// which the daemon turns into a NameOwnerChanged signal.
pub const Outcome = struct {
    result: RequestResult = .primary_owner,
    release_result: ReleaseResult = .released,
    changed: bool = false,
    old_owner: ?ConnId = null,
    new_owner: ?ConnId = null,
};

const Owner = struct {
    conn: ConnId,
    flags: RequestFlags,
};

const NameEntry = struct {
    owners: std.ArrayList(Owner), // owners[0] is the primary owner; rest is the queue

    fn primary(self: NameEntry) ?ConnId {
        if (self.owners.items.len == 0) return null;
        return self.owners.items[0].conn;
    }
    fn indexOf(self: NameEntry, conn: ConnId) ?usize {
        for (self.owners.items, 0..) |o, i| if (o.conn == conn) return i;
        return null;
    }
};

pub const NameRegistry = struct {
    gpa: std.mem.Allocator,
    counter: u32 = 0,
    names: std.StringHashMapUnmanaged(NameEntry) = .empty,

    pub fn init(gpa: std.mem.Allocator) NameRegistry {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *NameRegistry) void {
        var it = self.names.iterator();
        while (it.next()) |e| {
            e.value_ptr.owners.deinit(self.gpa);
            self.gpa.free(e.key_ptr.*);
        }
        self.names.deinit(self.gpa);
    }

    /// Allocate the next unique name (":1.N"). Caller owns the returned slice.
    pub fn nextUnique(self: *NameRegistry) std.mem.Allocator.Error![]u8 {
        self.counter += 1;
        return std.fmt.allocPrint(self.gpa, ":1.{d}", .{self.counter});
    }

    pub fn owner(self: *NameRegistry, name: []const u8) ?ConnId {
        const e = self.names.getPtr(name) orelse return null;
        return e.primary();
    }

    pub fn hasOwner(self: *NameRegistry, name: []const u8) bool {
        return self.owner(name) != null;
    }

    /// Request ownership of a well-known name.
    pub fn request(self: *NameRegistry, name: []const u8, conn: ConnId, flags: RequestFlags) std.mem.Allocator.Error!Outcome {
        const gop = try self.names.getOrPut(self.gpa, name);
        if (!gop.found_existing) {
            gop.key_ptr.* = try self.gpa.dupe(u8, name);
            gop.value_ptr.* = .{ .owners = .empty };
            try gop.value_ptr.owners.append(self.gpa, .{ .conn = conn, .flags = flags });
            return .{ .result = .primary_owner, .changed = true, .old_owner = null, .new_owner = conn };
        }

        const entry = gop.value_ptr;
        const primary = entry.owners.items[0];
        if (primary.conn == conn) {
            entry.owners.items[0].flags = flags; // refresh flags
            return .{ .result = .already_owner };
        }

        // Replacement: the current primary allows it and the requester asked.
        if (primary.flags.allow_replacement and flags.replace_existing) {
            const old = primary.conn;
            // If the requester was already queued, drop that stale slot first so
            // it does not end up owning the name twice.
            if (entry.indexOf(conn)) |qi| _ = entry.owners.orderedRemove(qi);
            // Demote the old primary into the queue front (unless it does-not-queue).
            if (primary.flags.do_not_queue) {
                _ = entry.owners.orderedRemove(0);
            } else {
                entry.owners.items[0] = .{ .conn = old, .flags = primary.flags };
            }
            try entry.owners.insert(self.gpa, 0, .{ .conn = conn, .flags = flags });
            // If the old owner does-not-queue we removed it above; otherwise it is
            // now at index 1.
            return .{ .result = .primary_owner, .changed = true, .old_owner = old, .new_owner = conn };
        }

        // Already in the queue?
        if (entry.indexOf(conn)) |_| {
            return .{ .result = .in_queue };
        }
        if (flags.do_not_queue) {
            return .{ .result = .exists };
        }
        try entry.owners.append(self.gpa, .{ .conn = conn, .flags = flags });
        return .{ .result = .in_queue };
    }

    /// Release a well-known name held or queued by `conn`.
    pub fn release(self: *NameRegistry, name: []const u8, conn: ConnId) Outcome {
        const entry = self.names.getPtr(name) orelse return .{ .release_result = .non_existent };
        const idx = entry.indexOf(conn) orelse return .{ .release_result = .not_owner };

        if (idx != 0) {
            _ = entry.owners.orderedRemove(idx);
            return .{ .release_result = .released };
        }
        // Releasing the primary: promote the next in queue, if any.
        _ = entry.owners.orderedRemove(0);
        const new_owner: ?ConnId = if (entry.owners.items.len > 0) entry.owners.items[0].conn else null;
        var out = Outcome{ .release_result = .released, .changed = true, .old_owner = conn, .new_owner = new_owner };
        if (new_owner == null) self.removeEntry(name);
        out.result = .primary_owner;
        return out;
    }

    fn removeEntry(self: *NameRegistry, name: []const u8) void {
        if (self.names.fetchRemove(name)) |kv| {
            var e = kv.value;
            e.owners.deinit(self.gpa);
            self.gpa.free(kv.key);
        }
    }

    /// Drop every name owned or queued by `conn` (on disconnect). Appends a
    /// primary-owner change to `changes` for each name whose primary owner moved.
    /// Each `changes[i].name` is heap-allocated; the caller must free it.
    pub fn releaseAll(self: *NameRegistry, conn: ConnId, changes: *std.ArrayList(OwnerChange)) std.mem.Allocator.Error!void {
        var to_remove: std.ArrayList([]const u8) = .empty;
        defer to_remove.deinit(self.gpa);

        var it = self.names.iterator();
        while (it.next()) |e| {
            const entry = e.value_ptr;
            const idx = entry.indexOf(conn) orelse continue;
            if (idx == 0) {
                _ = entry.owners.orderedRemove(0);
                const new_owner: ?ConnId = if (entry.owners.items.len > 0) entry.owners.items[0].conn else null;
                // Dupe the name: the entry (and its key) may be removed below, so
                // the caller must own the name it reports in `changes`.
                try changes.append(self.gpa, .{ .name = try self.gpa.dupe(u8, e.key_ptr.*), .old_owner = conn, .new_owner = new_owner });
                if (new_owner == null) try to_remove.append(self.gpa, e.key_ptr.*);
            } else {
                _ = entry.owners.orderedRemove(idx);
            }
        }
        for (to_remove.items) |name| self.removeEntry(name);
    }

    /// Collect all currently-owned well-known names into `list` (owned slices
    /// borrowed from the registry; valid until the name is released).
    pub fn list(self: *NameRegistry, gpa: std.mem.Allocator, out: *std.ArrayList([]const u8)) std.mem.Allocator.Error!void {
        var it = self.names.iterator();
        while (it.next()) |e| {
            if (e.value_ptr.owners.items.len > 0) try out.append(gpa, e.key_ptr.*);
        }
    }
};

pub const OwnerChange = struct {
    name: []const u8,
    old_owner: ?ConnId,
    new_owner: ?ConnId,
};

const testing = std.testing;

test "unique names increment" {
    var reg = NameRegistry.init(testing.allocator);
    defer reg.deinit();
    const a = try reg.nextUnique();
    defer testing.allocator.free(a);
    const b = try reg.nextUnique();
    defer testing.allocator.free(b);
    try testing.expectEqualStrings(":1.1", a);
    try testing.expectEqualStrings(":1.2", b);
}

test "request grants, queues, and releases with promotion" {
    var reg = NameRegistry.init(testing.allocator);
    defer reg.deinit();

    // conn 1 gets the name.
    var o = try reg.request("com.x", 1, .{});
    try testing.expectEqual(RequestResult.primary_owner, o.result);
    try testing.expectEqual(@as(?ConnId, 1), reg.owner("com.x"));

    // conn 1 again -> already owner.
    o = try reg.request("com.x", 1, .{});
    try testing.expectEqual(RequestResult.already_owner, o.result);

    // conn 2 queues (no do-not-queue).
    o = try reg.request("com.x", 2, .{});
    try testing.expectEqual(RequestResult.in_queue, o.result);

    // conn 3 with do-not-queue -> exists.
    o = try reg.request("com.x", 3, .{ .do_not_queue = true });
    try testing.expectEqual(RequestResult.exists, o.result);

    // conn 1 releases -> conn 2 promoted.
    const r = reg.release("com.x", 1);
    try testing.expectEqual(ReleaseResult.released, r.release_result);
    try testing.expect(r.changed);
    try testing.expectEqual(@as(?ConnId, 1), r.old_owner);
    try testing.expectEqual(@as(?ConnId, 2), r.new_owner);
    try testing.expectEqual(@as(?ConnId, 2), reg.owner("com.x"));
}

test "replace-existing when allowed" {
    var reg = NameRegistry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.request("com.y", 1, .{ .allow_replacement = true });
    const o = try reg.request("com.y", 2, .{ .replace_existing = true });
    try testing.expectEqual(RequestResult.primary_owner, o.result);
    try testing.expectEqual(@as(?ConnId, 1), o.old_owner);
    try testing.expectEqual(@as(?ConnId, 2), o.new_owner);
    try testing.expectEqual(@as(?ConnId, 2), reg.owner("com.y"));
}

test "replace by an already-queued connection does not duplicate ownership" {
    var reg = NameRegistry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.request("com.z", 1, .{ .allow_replacement = true });
    _ = try reg.request("com.z", 2, .{}); // conn 2 queued
    // conn 2 (already queued) now replaces conn 1.
    const o = try reg.request("com.z", 2, .{ .replace_existing = true });
    try testing.expectEqual(RequestResult.primary_owner, o.result);
    try testing.expectEqual(@as(?ConnId, 2), reg.owner("com.z"));
    // conn 2 releases -> conn 1 promoted; conn 2 must be entirely gone.
    _ = reg.release("com.z", 2);
    try testing.expectEqual(@as(?ConnId, 1), reg.owner("com.z"));
    try testing.expectEqual(ReleaseResult.not_owner, reg.release("com.z", 2).release_result);
}

test "releaseAll drops names and reports changes" {
    var reg = NameRegistry.init(testing.allocator);
    defer reg.deinit();
    _ = try reg.request("com.a", 1, .{});
    _ = try reg.request("com.b", 1, .{});
    _ = try reg.request("com.a", 2, .{}); // conn 2 queued on com.a

    var changes: std.ArrayList(OwnerChange) = .empty;
    defer changes.deinit(testing.allocator);
    defer for (changes.items) |ch| testing.allocator.free(ch.name);
    try reg.releaseAll(1, &changes);

    // com.a -> conn 2 promoted; com.b -> no owner.
    try testing.expectEqual(@as(?ConnId, 2), reg.owner("com.a"));
    try testing.expect(!reg.hasOwner("com.b"));
    try testing.expectEqual(@as(usize, 2), changes.items.len);
}
