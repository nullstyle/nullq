const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const boringssl_mod = boringssl_dep.module("boringssl");

    const nullq_mod = b.addModule("nullq", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    nullq_mod.addImport("boringssl", boringssl_mod);

    const test_step = b.step("test", "Run nullq tests");

    const unit_tests = b.addTest(.{ .root_module = nullq_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // Cross-cutting integration tests live in tests/. They have
    // their own module so they can `@embedFile` test data without
    // shipping it inside the published `nullq` package.
    const tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests_mod.addImport("nullq", nullq_mod);
    tests_mod.addImport("boringssl", boringssl_mod);
    const integration_tests = b.addTest(.{ .root_module = tests_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_step.dependOn(&run_integration_tests.step);

    const qns_mod = b.createModule(.{
        .root_source_file = b.path("interop/qns_endpoint.zig"),
        .target = target,
        .optimize = optimize,
    });
    qns_mod.addImport("nullq", nullq_mod);
    qns_mod.addImport("boringssl", boringssl_mod);

    const qns_exe = b.addExecutable(.{
        .name = "qns-endpoint",
        .root_module = qns_mod,
    });
    const qns_install = b.addInstallArtifact(qns_exe, .{});
    b.getInstallStep().dependOn(&qns_install.step);

    const qns_tests = b.addTest(.{ .root_module = qns_mod });
    const run_qns_tests = b.addRunArtifact(qns_tests);
    test_step.dependOn(&run_qns_tests.step);

    const qns_step = b.step("qns-endpoint", "Build the QUIC interop-runner endpoint");
    qns_step.dependOn(&qns_install.step);

    const interop_tool_mod = b.createModule(.{
        .root_source_file = b.path("tools/external_interop.zig"),
        .target = target,
        .optimize = optimize,
    });
    const interop_tool_exe = b.addExecutable(.{
        .name = "nullq-external-interop",
        .root_module = interop_tool_mod,
    });
    b.installArtifact(interop_tool_exe);

    const interop_tool_tests = b.addTest(.{ .root_module = interop_tool_mod });
    const run_interop_tool_tests = b.addRunArtifact(interop_tool_tests);
    test_step.dependOn(&run_interop_tool_tests.step);

    const run_interop_tool = b.addRunArtifact(interop_tool_exe);
    if (b.args) |args| run_interop_tool.addArgs(args);
    const external_interop_step = b.step("external-interop", "Run the external QUIC interop gate helper");
    external_interop_step.dependOn(&run_interop_tool.step);

    // Microbenchmarks. Always built with ReleaseFast (Debug-mode
    // numbers are meaningless), regardless of the user's
    // -Doptimize choice for the rest of the tree.
    //
    // We re-instantiate the nullq and boringssl modules under
    // ReleaseFast because BoringSSL compiled in Debug links UBSan
    // runtime symbols that the ReleaseFast linker won't resolve.
    const bench_optimize: std.builtin.OptimizeMode = .ReleaseFast;
    const bench_boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = bench_optimize,
    });
    const bench_boringssl_mod = bench_boringssl_dep.module("boringssl");

    const bench_nullq_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_nullq_mod.addImport("boringssl", bench_boringssl_mod);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_mod.addImport("nullq", bench_nullq_mod);
    bench_mod.addImport("boringssl", bench_boringssl_mod);

    const bench_exe = b.addExecutable(.{
        .name = "nullq-bench",
        .root_module = bench_mod,
    });
    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| run_bench.addArgs(args);
    const bench_step = b.step("bench", "Run nullq microbenchmarks");
    bench_step.dependOn(&run_bench.step);
}
