// zig-scanner/build.zig
//
// Ported to the Zig 0.14+ build API: `root_source_file` on
// `ExecutableOptions` was replaced by `root_module` (see std.Build in the
// 0.14 release notes). `b.createModule(...)` accepts the same
// target/optimize pair, so behaviour is unchanged for every older
// abstraction level that remains supported.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "zig-scanner",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            // libc linkage (previously `exe.linkLibC()` — that helper was
            // replaced by this module-level flag in the Zig 0.15/0.16 API).
            .link_libc = true,
        }),
    });

    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);

    const run_step = b.step("run", "Run the zig-scanner");
    run_step.dependOn(&run_cmd.step);
}
