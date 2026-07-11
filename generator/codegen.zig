//! Emit Zig bindings from a parsed introspection Document: a server `Vtable` (an
//! object.Interface built from typed handler trampolines) and a client `Proxy`
//! (typed async call senders plus typed reply decoders) per interface.
//!
//! Scope: methods whose arguments are all BASIC D-Bus types (the common case) and
//! with 0 or 1 out-arg get typed bindings; anything else is emitted as a comment
//! noting it was skipped, so generation never fails.

const std = @import("std");
const introspect = @import("introspect.zig");
const Document = introspect.Document;
const Interface = introspect.Interface;
const Method = introspect.Method;
const Arg = introspect.Arg;

const Buf = std.ArrayList(u8);

fn zigType(sig: []const u8) ?[]const u8 {
    if (sig.len != 1) return null;
    return switch (sig[0]) {
        'y' => "u8",
        'b' => "bool",
        'n' => "i16",
        'q' => "u16",
        'i' => "i32",
        'u' => "u32",
        'x' => "i64",
        't' => "u64",
        'd' => "f64",
        'h' => "u32",
        's', 'o', 'g' => "[]const u8",
        else => null,
    };
}

fn readerCall(sig: u8) []const u8 {
    return switch (sig) {
        'y' => "byte",
        'b' => "boolean",
        'n' => "int16",
        'q' => "uint16",
        'i' => "int32",
        'u' => "uint32",
        'x' => "int64",
        't' => "uint64",
        'd' => "double",
        'h' => "unixFd",
        's' => "string",
        'o' => "objectPath",
        'g' => "signatureStr",
        else => unreachable,
    };
}

fn writerCall(sig: u8) []const u8 {
    return switch (sig) {
        'y' => "byte",
        'b' => "boolean",
        'n' => "int16",
        'q' => "uint16",
        'i' => "int32",
        'u' => "uint32",
        'x' => "int64",
        't' => "uint64",
        'd' => "double",
        'h' => "unixFd",
        's' => "string",
        'o' => "objectPath",
        'g' => "signatureStr",
        else => unreachable,
    };
}

/// A valid Zig identifier from an interface name (dots/dashes -> underscores).
fn sanitize(gpa: std.mem.Allocator, name: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, name.len);
    for (name, 0..) |c, i| out[i] = if (std.ascii.isAlphanumeric(c)) c else '_';
    return out;
}

fn methodSupported(m: Method) bool {
    var outs: usize = 0;
    for (m.args) |a| {
        if (zigType(a.sig) == null) return false;
        if (a.dir == .out) outs += 1;
    }
    return outs <= 1;
}

fn inArgs(m: Method) usize {
    var n: usize = 0;
    for (m.args) |a| {
        if (a.dir == .in_) n += 1;
    }
    return n;
}

fn outArg(m: Method) ?Arg {
    for (m.args) |a| if (a.dir == .out) return a;
    return null;
}

pub fn generate(gpa: std.mem.Allocator, doc: Document) ![]u8 {
    var buf: Buf = .empty;
    errdefer buf.deinit(gpa);
    const w = &buf;

    try w.appendSlice(gpa,
        \\// Generated from D-Bus introspection XML. Do not edit.
        \\const std = @import("std");
        \\const dbus = @import("dbus");
        \\const Message = dbus.message.Message;
        \\const Reader = dbus.unmarshal.Reader;
        \\const Writer = dbus.marshal.Writer;
        \\const Interface = dbus.object.Interface;
        \\const Method = dbus.object.Method;
        \\const HandlerError = dbus.object.HandlerError;
        \\const Bus = dbus.client.Bus;
        \\
        \\
    );

    for (doc.node.interfaces) |iface| {
        const ident = try sanitize(gpa, iface.name);
        defer gpa.free(ident);
        try emitInterface(gpa, w, iface, ident);
    }

    return buf.toOwnedSlice(gpa);
}

fn emitInterface(gpa: std.mem.Allocator, w: *Buf, iface: Interface, ident: []const u8) !void {
    try w.print(gpa, "pub const {s} = struct {{\n", .{ident});
    try w.print(gpa, "    pub const name = \"{s}\";\n\n", .{iface.name});

    try emitVtable(gpa, w, iface);
    try emitProxy(gpa, w, iface);

    try w.appendSlice(gpa, "};\n\n");
}

fn emitVtable(gpa: std.mem.Allocator, w: *Buf, iface: Interface) !void {
    try w.appendSlice(gpa,
        \\    /// Server vtable: `Impl` supplies a method per interface method.
        \\    pub fn Vtable(comptime Impl: type) type {
        \\        return struct {
        \\            const Self = @This();
        \\
    );

    // Trampolines.
    for (iface.methods) |m| {
        if (!methodSupported(m)) {
            try w.print(gpa, "            // skipped method {s} (unsupported arg types)\n", .{m.name});
            continue;
        }

        var argi: usize = 0;
        for (m.args) |a| {
            if (a.dir == .in_) argi += 1;
        }

        try w.print(gpa, "            fn h_{s}(ctx: ?*anyopaque, call: *const Message, w: *Writer) HandlerError![]const u8 {{\n", .{m.name});
        try w.appendSlice(gpa, "                const self: *Impl = @ptrCast(@alignCast(ctx.?));\n");
        if (argi > 0) {
            var i: usize = 0;
            try w.appendSlice(gpa, "                var r = Reader.init(call.body, call.endian);\n");
            for (m.args) |a| {
                if (a.dir != .in_) continue;
                try w.print(gpa, "                const in{d} = r.{s}() catch return error.Failed;\n", .{ i, readerCall(a.sig[0]) });
                i += 1;
            }
        } else {
            try w.appendSlice(gpa, "                _ = call;\n");
        }
        // Call the impl.
        const out = outArg(m);
        if (out) |_| {
            try w.print(gpa, "                const ret = self.{s}(", .{m.name});
        } else {
            try w.print(gpa, "                self.{s}(", .{m.name});
        }
        var j: usize = 0;
        while (j < argi) : (j += 1) {
            if (j != 0) try w.appendSlice(gpa, ", ");
            try w.print(gpa, "in{d}", .{j});
        }
        try w.appendSlice(gpa, ");\n");
        if (out) |o| {
            try w.print(gpa, "                try w.{s}(ret);\n", .{writerCall(o.sig[0])});
            try w.print(gpa, "                return \"{s}\";\n", .{o.sig});
        } else {
            try w.appendSlice(gpa, "                _ = w;\n");
            try w.appendSlice(gpa, "                return \"\";\n");
        }
        try w.appendSlice(gpa, "            }\n");
    }

    // The method table + interface() builder (ctx bound to the impl instance).
    try w.appendSlice(gpa, "\n            methods: [n_methods]Method,\n");
    try w.appendSlice(gpa, "            pub fn init(impl: *Impl) Self {\n");

    for (iface.methods) |m| {
        if (methodSupported(m)) break;
    } else {
        try w.appendSlice(gpa, "                _ = impl;\n");
    }

    try w.appendSlice(gpa, "                return .{ .methods = .{\n");
    for (iface.methods) |m| {
        if (!methodSupported(m)) continue;
        try w.print(gpa, "                    .{{ .name = \"{s}\", .handler = h_{s}, .ctx = impl }},\n", .{ m.name, m.name });
    }
    try w.appendSlice(gpa, "                } };\n            }\n");
    try w.appendSlice(gpa, "            pub fn interface(self: *const Self) Interface {\n");
    try w.appendSlice(gpa, "                return .{ .name = name, .methods = &self.methods };\n            }\n");

    // Count of supported methods for the array length.
    var supported: usize = 0;
    for (iface.methods) |m| {
        if (methodSupported(m)) supported += 1;
    }
    try w.print(gpa, "            const n_methods = {d};\n", .{supported});
    try w.appendSlice(gpa, "        };\n    }\n\n");
}

fn emitProxy(gpa: std.mem.Allocator, w: *Buf, iface: Interface) !void {
    try w.appendSlice(gpa,
        \\    /// Client proxy: typed async call senders and typed reply decoders.
        \\    pub const Proxy = struct {
        \\        bus: *Bus,
        \\        destination: []const u8,
        \\        path: []const u8,
        \\        const ReplyFn = dbus.connection.ReplyFn;
        \\
    );

    for (iface.methods) |m| {
        if (!methodSupported(m)) {
            try w.print(gpa, "        // skipped method {s} (unsupported arg types)\n", .{m.name});
            continue;
        }
        // Reply struct + decoder.
        if (outArg(m)) |o| {
            try w.print(gpa, "        pub const {s}Reply = struct {{ value: {s} }};\n", .{ m.name, zigType(o.sig).? });
            try w.print(gpa, "        pub fn decode{s}(reply: *const Message) !{s}Reply {{\n", .{ m.name, m.name });
            try w.appendSlice(gpa, "            var r = Reader.init(reply.body, reply.endian);\n");
            try w.print(gpa, "            return .{{ .value = try r.{s}() }};\n        }}\n", .{readerCall(o.sig[0])});
        }
        // Call sender.
        try w.print(gpa, "        pub fn {s}(self: *Proxy", .{m.name});
        var argi: usize = 0;
        for (m.args) |a| {
            if (a.dir != .in_) continue;
            try w.print(gpa, ", in{d}: {s}", .{ argi, zigType(a.sig).? });
            argi += 1;
        }
        try w.appendSlice(gpa, ", cb: ReplyFn, ctx: ?*anyopaque) !u32 {\n");
        try w.appendSlice(gpa, "            var body: std.ArrayList(u8) = .empty;\n");
        try w.appendSlice(gpa, "            defer body.deinit(self.bus.gpa);\n");
        var in_sig: Buf = .empty;
        defer in_sig.deinit(gpa);
        if (argi > 0) {
            try w.appendSlice(gpa, "            var bw = Writer.init(self.bus.gpa, &body, self.bus.conn.endian);\n");
            var j: usize = 0;
            for (m.args) |a| {
                if (a.dir != .in_) continue;
                try w.print(gpa, "            try bw.{s}(in{d});\n", .{ writerCall(a.sig[0]), j });
                try in_sig.appendSlice(gpa, a.sig);
                j += 1;
            }
        }
        try w.print(gpa, "            const msg = Message{{ .msg_type = .method_call, .serial = 0, .path = self.path, .interface = name, .member = \"{s}\", .destination = self.destination", .{m.name});
        if (in_sig.items.len > 0) {
            try w.print(gpa, ", .body_signature = \"{s}\", .body = body.items", .{in_sig.items});
        }
        try w.appendSlice(gpa, " };\n");
        try w.appendSlice(gpa, "            return self.bus.call(msg, cb, ctx);\n        }\n");
    }

    try w.appendSlice(gpa, "    };\n");
}

const testing = std.testing;

test "generate produces vtable and proxy for a basic interface" {
    const xml =
        \\<node>
        \\  <interface name="org.example.Calc">
        \\    <method name="Add">
        \\      <arg name="a" type="i" direction="in"/>
        \\      <arg name="b" type="i" direction="in"/>
        \\      <arg name="sum" type="i" direction="out"/>
        \\    </method>
        \\    <method name="Reset"/>
        \\  </interface>
        \\</node>
    ;
    var doc = try introspect.parse(testing.allocator, xml);
    defer doc.deinit();
    const src = try generate(testing.allocator, doc);
    defer testing.allocator.free(src);

    try testing.expect(std.mem.indexOf(u8, src, "pub const org_example_Calc = struct") != null);
    try testing.expect(std.mem.indexOf(u8, src, "pub fn Vtable(comptime Impl: type) type") != null);
    try testing.expect(std.mem.indexOf(u8, src, "fn h_Add(") != null);
    try testing.expect(std.mem.indexOf(u8, src, "self.Add(in0, in1)") != null);
    try testing.expect(std.mem.indexOf(u8, src, "pub fn Add(self: *Proxy, in0: i32, in1: i32") != null);
    try testing.expect(std.mem.indexOf(u8, src, "pub const AddReply = struct { value: i32 }") != null);
    try testing.expect(std.mem.indexOf(u8, src, "pub fn Reset(self: *Proxy") != null);
}
