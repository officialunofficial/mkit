const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const use_jemalloc = b.option(bool, "jemalloc", "Use jemalloc allocator (requires system jemalloc)") orelse false;

    // Build options module (shared between exe and lib)
    const options = b.addOptions();
    options.addOption(bool, "use_jemalloc", use_jemalloc);

    // Library module
    const lib_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Executable module
    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    exe_mod.addImport("mkit", lib_mod);
    exe_mod.addOptions("build_options", options);

    if (use_jemalloc) {
        exe_mod.linkSystemLibrary("jemalloc", .{});
        exe_mod.link_libc = true;
    }

    const exe = b.addExecutable(.{
        .name = "mkit",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    // Run step
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run mkit");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const test_step = b.step("test", "Run unit tests");

    const test_mod = b.createModule(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    const lib_tests = b.addTest(.{
        .root_module = test_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    test_step.dependOn(&run_lib_tests.step);

    // Integration tests
    const test_integration_step = b.step("test-integration", "Run integration tests");

    const integration_test_mod = b.createModule(.{
        .root_source_file = b.path("src/integration_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    const integration_tests = b.addTest(.{
        .root_module = integration_test_mod,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_integration_step.dependOn(&run_integration_tests.step);

    // Combined test-all step (unit + integration).
    const test_all_step = b.step("test-all", "Run all tests (unit + integration)");
    test_all_step.dependOn(&run_lib_tests.step);
    test_all_step.dependOn(&run_integration_tests.step);

    // Benchmark step (always ReleaseFast for meaningful numbers)
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    const bench_exe = b.addExecutable(.{
        .name = "mkit-bench",
        .root_module = bench_mod,
    });
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks (ReleaseFast)");
    bench_step.dependOn(&run_bench.step);

    // Format step
    const fmt = b.addFmt(.{
        .paths = &.{ "src/", "build.zig" },
    });
    const fmt_step = b.step("fmt", "Format source files");
    fmt_step.dependOn(&fmt.step);

    // Check step (format verification)
    const fmt_check = b.addFmt(.{
        .paths = &.{ "src/", "build.zig" },
        .check = true,
    });
    const check_step = b.step("check", "Check formatting");
    check_step.dependOn(&fmt_check.step);
}
