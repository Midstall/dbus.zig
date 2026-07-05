//! Root of the pure-Zig D-Bus library (one `dbus` module). Consumers reach the
//! pieces as namespaces: `dbus.types`, `dbus.signature`, `dbus.marshal`,
//! `dbus.unmarshal`, `dbus.message`.

const std = @import("std");

pub const types = @import("dbus/types.zig");
pub const signature = @import("dbus/signature.zig");
pub const marshal = @import("dbus/marshal.zig");
pub const unmarshal = @import("dbus/unmarshal.zig");
pub const message = @import("dbus/message.zig");
pub const address = @import("dbus/address.zig");
pub const event_loop = @import("dbus/event_loop.zig");
pub const transport = @import("dbus/transport.zig");
pub const auth = @import("dbus/auth.zig");
pub const connection = @import("dbus/connection.zig");
pub const client = @import("dbus/client.zig");
pub const match = @import("dbus/match.zig");
pub const object = @import("dbus/object.zig");
pub const interfaces = @import("dbus/interfaces.zig");
pub const daemon = @import("dbus/daemon.zig");

pub const Type = types.Type;
pub const Writer = marshal.Writer;
pub const Reader = unmarshal.Reader;
pub const Value = unmarshal.Value;
pub const Message = message.Message;

test {
    std.testing.refAllDecls(@This());
}
