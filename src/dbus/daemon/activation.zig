//! Service activation: parse `.service` files ([D-BUS Service] with Name=/Exec=),
//! index them by name, and spawn a service's Exec on demand via double-fork +
//! execve (so no zombie is left behind). Env/starter-address propagation and
//! auto-start message queuing are follow-ups; this provides the parse + spawn
//! machinery and explicit StartServiceByName.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;

pub const Error = error{ Malformed, SpawnFailed } || std.mem.Allocator.Error;

pub const Service = struct {
    name: []const u8,
    exec: []const u8,

    fn deinit(self: Service, gpa: std.mem.Allocator) void {
        gpa.free(self.name);
        gpa.free(self.exec);
    }
};

/// Parse a `.service` file body. Returns the Name and Exec, both duped.
pub fn parseService(gpa: std.mem.Allocator, body: []const u8) Error!Service {
    var name: ?[]const u8 = null;
    var exec: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, body, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#' or line[0] == '[') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = std.mem.trim(u8, line[0..eq], " \t");
        const val = std.mem.trim(u8, line[eq + 1 ..], " \t");
        if (std.mem.eql(u8, key, "Name")) name = val;
        if (std.mem.eql(u8, key, "Exec")) exec = val;
    }
    const n = name orelse return Error.Malformed;
    const e = exec orelse return Error.Malformed;
    const name_owned = try gpa.dupe(u8, n);
    errdefer gpa.free(name_owned);
    return .{ .name = name_owned, .exec = try gpa.dupe(u8, e) };
}

pub const ServiceRegistry = struct {
    gpa: std.mem.Allocator,
    services: std.ArrayList(Service) = .empty,

    pub fn init(gpa: std.mem.Allocator) ServiceRegistry {
        return .{ .gpa = gpa };
    }

    pub fn deinit(self: *ServiceRegistry) void {
        for (self.services.items) |s| s.deinit(self.gpa);
        self.services.deinit(self.gpa);
    }

    pub fn add(self: *ServiceRegistry, body: []const u8) Error!void {
        const svc = try parseService(self.gpa, body);
        errdefer svc.deinit(self.gpa);
        try self.services.append(self.gpa, svc);
    }

    pub fn lookup(self: *ServiceRegistry, name: []const u8) ?Service {
        for (self.services.items) |s| {
            if (std.mem.eql(u8, s.name, name)) return s;
        }
        return null;
    }

    pub fn names(self: *ServiceRegistry, gpa: std.mem.Allocator, out: *std.ArrayList([]const u8)) Error!void {
        for (self.services.items) |s| try out.append(gpa, s.name);
    }
};

/// Spawn `exec` (a space-separated command line) as a detached process using a
/// double fork so the caller need not reap it. Returns on success once the
/// intermediate child has been reaped.
pub fn spawn(gpa: std.mem.Allocator, exec: []const u8) Error!void {
    // Build a null-terminated argv of null-terminated strings.
    var args: std.ArrayList([:0]u8) = .empty;
    defer {
        for (args.items) |a| gpa.free(a);
        args.deinit(gpa);
    }
    var it = std.mem.tokenizeScalar(u8, exec, ' ');
    while (it.next()) |tok| try args.append(gpa, try gpa.dupeZ(u8, tok));
    if (args.items.len == 0) return Error.SpawnFailed;

    const argv = try gpa.alloc(?[*:0]const u8, args.items.len + 1);
    defer gpa.free(argv);
    for (args.items, 0..) |a, i| argv[i] = a.ptr;
    argv[args.items.len] = null;

    var envp = [_:null]?[*:0]const u8{};

    const pid1 = linux.fork();
    if (@as(isize, @bitCast(pid1)) < 0) return Error.SpawnFailed;
    if (pid1 == 0) {
        // Intermediate child: fork again, then exit so the grandchild reparents.
        const pid2 = linux.fork();
        if (pid2 == 0) {
            _ = linux.execve(argv[0].?, @ptrCast(argv.ptr), &envp);
            linux.exit(127); // exec failed
        }
        linux.exit(0);
    }
    // Parent: reap the intermediate child (the grandchild is init's problem).
    var status: u32 = undefined;
    _ = linux.waitpid(@intCast(pid1), &status, 0);
}

const testing = std.testing;

test "parse a .service file" {
    const body =
        \\[D-BUS Service]
        \\Name=org.example.Test
        \\Exec=/usr/bin/example-service --bus
    ;
    var svc = try parseService(testing.allocator, body);
    defer svc.deinit(testing.allocator);
    try testing.expectEqualStrings("org.example.Test", svc.name);
    try testing.expectEqualStrings("/usr/bin/example-service --bus", svc.exec);
}

test "registry indexes and looks up services" {
    var reg = ServiceRegistry.init(testing.allocator);
    defer reg.deinit();
    try reg.add("[D-BUS Service]\nName=com.a.One\nExec=/bin/one");
    try reg.add("[D-BUS Service]\nName=com.b.Two\nExec=/bin/two");
    try testing.expectEqualStrings("/bin/two", reg.lookup("com.b.Two").?.exec);
    try testing.expect(reg.lookup("com.c.None") == null);
}

test "spawn runs a command" {
    // Spawn `touch <tmpfile>` and confirm the file appears.
    const pid = linux.getpid();
    var path_buf: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buf, "/tmp/dbuszig-spawn-{d}", .{pid});
    var z_buf: [98]u8 = undefined;
    const pz = try std.fmt.bufPrint(&z_buf, "{s}\x00", .{path});
    _ = linux.unlinkat(linux.AT.FDCWD, @ptrCast(pz.ptr), 0);

    // Find a touch binary.
    const touch = for ([_][]const u8{ "/usr/bin/touch", "/run/current-system/sw/bin/touch", "/bin/touch" }) |t| {
        var tb: [64]u8 = undefined;
        const tz = try std.fmt.bufPrint(&tb, "{s}\x00", .{t});
        const rc = linux.faccessat(linux.AT.FDCWD, @ptrCast(tz.ptr), 0, 0);
        if (posix.errno(rc) == .SUCCESS) break t;
    } else return error.SkipZigTest;

    var cmd_buf: [160]u8 = undefined;
    const cmd = try std.fmt.bufPrint(&cmd_buf, "{s} {s}", .{ touch, path });
    try spawn(testing.allocator, cmd);

    // The grandchild runs asynchronously; poll briefly for the file.
    var appeared = false;
    var i: usize = 0;
    while (i < 100000) : (i += 1) {
        const rc = linux.faccessat(linux.AT.FDCWD, @ptrCast(pz.ptr), 0, 0);
        if (posix.errno(rc) == .SUCCESS) {
            appeared = true;
            break;
        }
    }
    _ = linux.unlinkat(linux.AT.FDCWD, @ptrCast(pz.ptr), 0);
    try testing.expect(appeared);
}
