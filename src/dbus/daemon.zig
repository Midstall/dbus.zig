//! The message-bus daemon: name registry, routing, the org.freedesktop.DBus
//! driver, config/policy, and service activation. Built on the same core as the
//! client.

const std = @import("std");

pub const names = @import("daemon/names.zig");
pub const bus = @import("daemon/bus.zig");
pub const driver = @import("daemon/driver.zig");
pub const config = @import("daemon/config.zig");
pub const policy = @import("daemon/policy.zig");
pub const activation = @import("daemon/activation.zig");

test {
    std.testing.refAllDecls(@This());
}
