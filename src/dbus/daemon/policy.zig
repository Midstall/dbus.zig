//! Policy evaluation over a parsed busconfig: may a connection send to a
//! destination / interface / member, and may it own a name. With no config the
//! bus is permissive (session-style). User/group policies are resolved only for
//! "root" (uid 0); other principals are conservatively skipped (a documented
//! limitation until uid->name resolution is wired).

const std = @import("std");
const config = @import("config.zig");
const Config = config.Config;
const Policy = config.Policy;
const Rule = config.Rule;

const context_order = [_]config.PolicyContext{ .default, .group, .user, .mandatory };

pub const PolicySet = struct {
    /// Borrowed config, or null for allow-all.
    config: ?*const Config = null,

    fn applicable(p: *const Policy, uid: u32) bool {
        return switch (p.context) {
            .default, .mandatory => true,
            .user => if (p.principal) |name| (std.mem.eql(u8, name, "root") and uid == 0) else false,
            .group => false, // group resolution not yet available
        };
    }

    /// May `uid` send a message to `dest` (interface/member optional)?
    pub fn canSend(self: PolicySet, uid: u32, dest: ?[]const u8, interface: ?[]const u8, member: ?[]const u8) bool {
        const cfg = self.config orelse return true;
        var decision = true; // permissive base
        for (context_order) |ctx| {
            for (cfg.policies.items) |*p| {
                if (p.context != ctx or !applicable(p, uid)) continue;
                for (p.rules.items) |*r| {
                    if (ruleAppliesToSend(r) and sendMatches(r, dest, interface, member)) {
                        decision = (r.kind == .allow);
                    }
                }
            }
        }
        return decision;
    }

    /// May `uid` own the well-known name `name`?
    pub fn canOwn(self: PolicySet, uid: u32, name: []const u8) bool {
        const cfg = self.config orelse return true;
        var decision = true;
        for (context_order) |ctx| {
            for (cfg.policies.items) |*p| {
                if (p.context != ctx or !applicable(p, uid)) continue;
                for (p.rules.items) |*r| {
                    if (r.own) |o| {
                        if (wildcardMatch(o, name)) decision = (r.kind == .allow);
                    }
                    if (r.own_prefix) |pre| {
                        if (std.mem.startsWith(u8, name, pre)) decision = (r.kind == .allow);
                    }
                }
            }
        }
        return decision;
    }
};

fn ruleAppliesToSend(r: *const Rule) bool {
    return r.send_destination != null or r.send_interface != null or r.send_member != null;
}

fn wildcardMatch(pat: []const u8, val: []const u8) bool {
    if (std.mem.eql(u8, pat, "*")) return true;
    return std.mem.eql(u8, pat, val);
}

fn optMatch(pat: ?[]const u8, val: ?[]const u8) bool {
    const p = pat orelse return true; // predicate absent -> matches
    if (std.mem.eql(u8, p, "*")) return true;
    const v = val orelse return false;
    return std.mem.eql(u8, p, v);
}

fn sendMatches(r: *const Rule, dest: ?[]const u8, interface: ?[]const u8, member: ?[]const u8) bool {
    return optMatch(r.send_destination, dest) and
        optMatch(r.send_interface, interface) and
        optMatch(r.send_member, member);
}

const testing = std.testing;

test "no config allows everything" {
    const ps = PolicySet{};
    try testing.expect(ps.canSend(1000, "org.any", "a.b", "M"));
    try testing.expect(ps.canOwn(1000, "com.any"));
}

test "deny rule blocks a matching send, allow base passes the rest" {
    const xml =
        \\<busconfig>
        \\  <policy context="default">
        \\    <allow own="*"/>
        \\    <deny send_interface="org.secret.Iface"/>
        \\    <deny own="com.reserved.Name"/>
        \\  </policy>
        \\</busconfig>
    ;
    var cfg = try config.parse(testing.allocator, xml);
    defer cfg.deinit();
    const ps = PolicySet{ .config = &cfg };

    // Sending to the secret interface is denied; other sends allowed.
    try testing.expect(!ps.canSend(1000, "org.x", "org.secret.Iface", "M"));
    try testing.expect(ps.canSend(1000, "org.x", "org.normal.Iface", "M"));

    // Owning the reserved name is denied; others allowed (allow own="*").
    try testing.expect(!ps.canOwn(1000, "com.reserved.Name"));
    try testing.expect(ps.canOwn(1000, "com.other.Name"));
}

test "user policy applies only to the matching uid" {
    const xml =
        \\<busconfig>
        \\  <policy user="root">
        \\    <deny send_destination="com.root.Guard"/>
        \\  </policy>
        \\</busconfig>
    ;
    var cfg = try config.parse(testing.allocator, xml);
    defer cfg.deinit();
    const ps = PolicySet{ .config = &cfg };

    try testing.expect(!ps.canSend(0, "com.root.Guard", null, null)); // root denied
    try testing.expect(ps.canSend(1000, "com.root.Guard", null, null)); // non-root unaffected
}
