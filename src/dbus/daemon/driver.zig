//! The org.freedesktop.DBus bus driver: the methods a client calls on the bus
//! itself. Handlers run inside the daemon's per-client dispatch and reply on the
//! client's connection (sender = org.freedesktop.DBus).

const std = @import("std");
const message = @import("../message.zig");
const Message = message.Message;
const marshal = @import("../marshal.zig");
const unmarshal = @import("../unmarshal.zig");
const match = @import("../match.zig");
const conn_mod = @import("../connection.zig");
const Connection = conn_mod.Connection;
const bus = @import("bus.zig");
const Daemon = bus.Daemon;
const Client = bus.Client;
const names = @import("names.zig");
const activation = @import("activation.zig");

pub const Error = conn_mod.Error;

const bus_name = "org.freedesktop.DBus";

pub fn handle(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    const member = msg.member orelse return;

    if (eql(member, "Hello")) {
        try replyOneString(client, msg, client.unique_name, "s");
        // Announce our own arrival to subscribers, and to ourselves.
        d.emitNameOwnerChanged(client.unique_name, "", client.unique_name);
        d.sendDirectedSignal(client, "NameAcquired", client.unique_name);
        return;
    } else if (eql(member, "GetId")) {
        try replyOneString(client, msg, &d.guid, "s");
        return;
    } else if (eql(member, "RequestName")) {
        try requestName(d, client, msg);
        return;
    } else if (eql(member, "ReleaseName")) {
        try releaseName(d, client, msg);
        return;
    } else if (eql(member, "ListNames")) {
        try listNames(d, client, msg, false);
        return;
    } else if (eql(member, "ListActivatableNames")) {
        try listNames(d, client, msg, true);
        return;
    } else if (eql(member, "NameHasOwner")) {
        try nameHasOwner(d, client, msg);
        return;
    } else if (eql(member, "GetNameOwner")) {
        try getNameOwner(d, client, msg);
        return;
    } else if (eql(member, "GetConnectionUnixUser")) {
        try connProp(d, client, msg, .uid);
        return;
    } else if (eql(member, "GetConnectionUnixProcessID")) {
        try connProp(d, client, msg, .pid);
        return;
    } else if (eql(member, "GetConnectionCredentials")) {
        try connCredentials(d, client, msg);
        return;
    } else if (eql(member, "AddMatch")) {
        try addMatch(d, client, msg);
        return;
    } else if (eql(member, "RemoveMatch")) {
        try removeMatch(d, client, msg);
        return;
    } else if (eql(member, "StartServiceByName")) {
        try startService(d, client, msg);
        return;
    } else if (eql(member, "UpdateActivationEnvironment")) {
        try replyEmpty(client, msg);
        return;
    }
    d.replyError(client, msg, "org.freedesktop.DBus.Error.UnknownMethod", "Unknown driver method");
}

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

fn sendReply(client: *Client, call: *const Message, sig: ?[]const u8, body: []const u8) Error!void {
    if (call.flags.no_reply_expected) return;
    const reply = Message{
        .msg_type = .method_return,
        .serial = 0,
        .reply_serial = call.serial,
        .sender = bus_name,
        .destination = client.unique_name,
        .body_signature = sig,
        .body = body,
    };
    _ = try client.conn.sendMessage(reply);
}

fn replyEmpty(client: *Client, call: *const Message) Error!void {
    try sendReply(client, call, null, "");
}

fn replyOneString(client: *Client, call: *const Message, s: []const u8, sig: []const u8) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.conn.gpa);
    var w = marshal.Writer.init(client.conn.gpa, &body, client.conn.endian);
    if (sig[0] == 'o') try w.objectPath(s) else try w.string(s);
    try sendReply(client, call, sig, body.items);
}

fn replyU32(client: *Client, call: *const Message, v: u32) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.conn.gpa);
    var w = marshal.Writer.init(client.conn.gpa, &body, client.conn.endian);
    try w.uint32(v);
    try sendReply(client, call, "u", body.items);
}

fn replyBool(client: *Client, call: *const Message, v: bool) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.conn.gpa);
    var w = marshal.Writer.init(client.conn.gpa, &body, client.conn.endian);
    try w.boolean(v);
    try sendReply(client, call, "b", body.items);
}

fn firstString(msg: *const Message) ?[]const u8 {
    var r = unmarshal.Reader.init(msg.body, msg.endian);
    return r.string() catch null;
}

fn requestName(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    var r = unmarshal.Reader.init(msg.body, msg.endian);
    const name = r.string() catch return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    const flags_u = r.uint32() catch return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    const flags: names.RequestFlags = @bitCast(flags_u);

    if (!d.mayOwn(client, name)) {
        return d.replyError(client, msg, "org.freedesktop.DBus.Error.AccessDenied", "Not allowed to own this name");
    }

    const outcome = d.registry.request(name, client.id, flags) catch return d.replyError(client, msg, "org.freedesktop.DBus.Error.NoMemory", "oom");
    if (outcome.changed) {
        const old_name = if (outcome.old_owner) |o| (if (d.clients.get(o)) |c| c.unique_name else "") else "";
        d.emitNameOwnerChanged(name, old_name, client.unique_name);
        d.sendDirectedSignal(client, "NameAcquired", name);
        if (outcome.old_owner) |o| if (d.clients.get(o)) |oc| d.sendDirectedSignal(oc, "NameLost", name);
    }
    try replyU32(client, msg, @intFromEnum(outcome.result));
}

fn releaseName(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    const name = firstString(msg) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    const outcome = d.registry.release(name, client.id);
    if (outcome.changed) {
        const new_name = if (outcome.new_owner) |n| (if (d.clients.get(n)) |c| c.unique_name else "") else "";
        d.emitNameOwnerChanged(name, client.unique_name, new_name);
        if (outcome.new_owner) |n| if (d.clients.get(n)) |nc| d.sendDirectedSignal(nc, "NameAcquired", name);
        d.sendDirectedSignal(client, "NameLost", name);
    }
    try replyU32(client, msg, @intFromEnum(outcome.release_result));
}

fn listNames(d: *Daemon, client: *Client, msg: *const Message, activatable: bool) Error!void {
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.conn.gpa);
    var w = marshal.Writer.init(client.conn.gpa, &body, client.conn.endian);
    const actx = try w.beginArray(4);
    try w.string(bus_name);
    if (activatable) {
        for (d.services.services.items) |svc| try w.string(svc.name);
    } else {
        var cit = d.clients.valueIterator();
        while (cit.next()) |cptr| try w.string(cptr.*.unique_name);
        var wk: std.ArrayList([]const u8) = .empty;
        defer wk.deinit(client.conn.gpa);
        try d.registry.list(client.conn.gpa, &wk);
        for (wk.items) |name| try w.string(name);
    }
    w.endArray(actx);
    try sendReply(client, msg, "as", body.items);
}

fn nameHasOwner(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    const name = firstString(msg) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    const has = eql(name, bus_name) or (d.resolve(name) != null);
    try replyBool(client, msg, has);
}

fn getNameOwner(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    const name = firstString(msg) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    if (eql(name, bus_name)) return replyOneString(client, msg, bus_name, "s");
    const target = d.resolve(name) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.NameHasNoOwner", "no owner");
    try replyOneString(client, msg, target.unique_name, "s");
}

const ConnQuery = enum { uid, pid };

fn connProp(d: *Daemon, client: *Client, msg: *const Message, q: ConnQuery) Error!void {
    const name = firstString(msg) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    const target = d.resolve(name) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.NameHasNoOwner", "no owner");
    const v: u32 = switch (q) {
        .uid => target.uid,
        .pid => @intCast(target.pid),
    };
    try replyU32(client, msg, v);
}

fn connCredentials(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    const name = firstString(msg) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    const target = d.resolve(name) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.NameHasNoOwner", "no owner");

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(client.conn.gpa);
    var w = marshal.Writer.init(client.conn.gpa, &body, client.conn.endian);
    const actx = try w.beginArray(8);
    try dictU32(&w, "UnixUserID", target.uid);
    try dictU32(&w, "ProcessID", @intCast(target.pid));
    w.endArray(actx);
    try sendReply(client, msg, "a{sv}", body.items);
}

fn dictU32(w: *marshal.Writer, key: []const u8, v: u32) Error!void {
    try w.beginStruct();
    try w.string(key);
    try w.beginVariant("u");
    try w.uint32(v);
}

fn addMatch(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    const rule_str = firstString(msg) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    const rule = match.parse(d.gpa, rule_str) catch return d.replyError(client, msg, "org.freedesktop.DBus.Error.MatchRuleInvalid", "bad rule");
    try client.matches.append(d.gpa, rule);
    try replyEmpty(client, msg);
}

fn removeMatch(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    const rule_str = firstString(msg) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    var want = match.parse(d.gpa, rule_str) catch return d.replyError(client, msg, "org.freedesktop.DBus.Error.MatchRuleInvalid", "bad rule");
    defer want.deinitOwned(d.gpa);
    const want_s = want.toString(d.gpa) catch return d.replyError(client, msg, "org.freedesktop.DBus.Error.NoMemory", "oom");
    defer d.gpa.free(want_s);

    for (client.matches.items, 0..) |*have, i| {
        const have_s = have.toString(d.gpa) catch continue;
        defer d.gpa.free(have_s);
        if (eql(have_s, want_s)) {
            have.deinitOwned(d.gpa);
            _ = client.matches.orderedRemove(i);
            return replyEmpty(client, msg);
        }
    }
    d.replyError(client, msg, "org.freedesktop.DBus.Error.MatchRuleNotFound", "no such rule");
}

fn startService(d: *Daemon, client: *Client, msg: *const Message) Error!void {
    const name = firstString(msg) orelse return d.replyError(client, msg, "org.freedesktop.DBus.Error.InvalidArgs", "bad args");
    if (d.resolve(name) != null) {
        try replyU32(client, msg, 2); // DBUS_START_REPLY_ALREADY_RUNNING
        return;
    }
    if (d.services.lookup(name)) |svc| {
        activation.spawn(d.gpa, svc.exec) catch return d.replyError(client, msg, "org.freedesktop.DBus.Error.Spawn.ExecFailed", "spawn failed");
        try replyU32(client, msg, 1); // DBUS_START_REPLY_SUCCESS
        return;
    }
    d.replyError(client, msg, "org.freedesktop.DBus.Error.ServiceUnknown", "service not found");
}
