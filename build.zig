const std = @import("std");

/// Turn a D-Bus introspection XML file into an importable Zig bindings module.
/// Downstream consumers call this from their own build.zig:
///
///   const dbus_dep = b.dependency("dbus", .{});
///   const calc = @import("dbus").generateBindings(b, dbus_dep, calc_xml, "calc");
///   my_module.addImport("calc", calc);
///
/// The generated module imports the core as "dbus".
pub fn generateBindings(
    owner: *std.Build,
    dbus_dep: *std.Build.Dependency,
    xml: std.Build.LazyPath,
    module_name: []const u8,
) *std.Build.Module {
    const run = owner.addRunArtifact(dbus_dep.artifact("dbus-gen"));
    run.addFileArg(xml);
    const out = run.addOutputFileArg(owner.fmt("{s}.zig", .{module_name}));
    const mod = owner.createModule(.{ .root_source_file = out });
    mod.addImport("dbus", dbus_dep.module("dbus"));
    return mod;
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const dbus_mod = b.addModule("dbus", .{
        .root_source_file = b.path("src/dbus.zig"),
        .target = target,
        .optimize = optimize,
    });

    const test_step = b.step("test", "Run tests");
    const dbus_tests = b.addTest(.{ .root_module = dbus_mod });
    test_step.dependOn(&b.addRunArtifact(dbus_tests).step);

    // Generator tests (the introspection parser + codegen run on the host).
    const gen_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("generator/introspect.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    test_step.dependOn(&b.addRunArtifact(gen_tests).step);

    // The pure-Zig dbus-daemon executable.
    const daemon_exe = b.addExecutable(.{
        .name = "dbus-daemon",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/dbus-daemon.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    daemon_exe.root_module.addImport("dbus", dbus_mod);
    b.installArtifact(daemon_exe);

    // The introspection-XML binding generator.
    const gen_exe = b.addExecutable(.{
        .name = "dbus-gen",
        .root_module = b.createModule(.{
            .root_source_file = b.path("generator/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(gen_exe);

    // Generate bindings for the vendored Calc interface and drive a proxy <->
    // vtable round-trip through our daemon, proving the generated code compiles
    // and works end to end.
    const gen_run = b.addRunArtifact(gen_exe);
    gen_run.addFileArg(b.path("test/calc.xml"));
    const calc_out = gen_run.addOutputFileArg("calc.zig");
    const calc_mod = b.createModule(.{
        .root_source_file = calc_out,
        .target = target,
        .optimize = optimize,
    });
    calc_mod.addImport("dbus", dbus_mod);

    const roundtrip_mod = b.createModule(.{
        .root_source_file = b.path("test/generated_roundtrip.zig"),
        .target = target,
        .optimize = optimize,
    });
    roundtrip_mod.addImport("dbus", dbus_mod);
    roundtrip_mod.addImport("calc", calc_mod);
    test_step.dependOn(&b.addRunArtifact(b.addTest(.{ .root_module = roundtrip_mod })).step);
}
