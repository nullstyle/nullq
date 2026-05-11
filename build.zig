const std = @import("std");

// Build-mode policy (hardening guide §3.1).
//
// `b.standardOptimizeOption` defaults to `Debug` so iterative
// development (`zig build test`, embedder smoke runs, interop
// fixtures) is fast and prints useful panic stacks. **Production /
// internet-facing builds MUST pass `-Doptimize=ReleaseSafe`** to
// keep Zig's runtime safety checks enabled (integer overflow,
// out-of-bounds slicing, optional unwrap, `unreachable`,
// `@setRuntimeSafety` toggles) while optimizing.
//
// `ReleaseFast` and `ReleaseSmall` are forbidden by default for the
// network-input parser surface. Both compile out runtime safety,
// which means the residual `unreachable` paths in `wire/`, `frame/`,
// and `conn/state.zig` (documented as non-peer-reachable invariants)
// stop being trapped — `unreachable` becomes "the optimizer assumes
// this is impossible". An adversarial input that reaches one of those
// sites in `ReleaseFast` produces undefined behavior instead of a
// controlled panic. The benchmark harness below defaults to
// `ReleaseSafe`; use `-Dbench-unsafe-release-fast=true` only when you
// intentionally want unsafe peak-speed measurements.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = optimize,
    });
    const boringssl_mod = boringssl_dep.module("boringssl");

    const quic_zig_mod = b.addModule("quic_zig", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    quic_zig_mod.addImport("boringssl", boringssl_mod);

    const test_step = b.step("test", "Run quic_zig tests");

    const unit_tests = b.addTest(.{ .root_module = quic_zig_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    test_step.dependOn(&run_unit_tests.step);

    // Cross-cutting integration tests live in tests/. They have
    // their own module so they can `@embedFile` test data without
    // shipping it inside the published `quic_zig` package.
    const tests_mod = b.createModule(.{
        .root_source_file = b.path("tests/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    tests_mod.addImport("quic_zig", quic_zig_mod);
    tests_mod.addImport("boringssl", boringssl_mod);
    const integration_tests = b.addTest(.{ .root_module = tests_mod });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    test_step.dependOn(&run_integration_tests.step);

    // RFC-traceable conformance suites under tests/conformance/. Each
    // file mirrors a section of an RFC and uses BCP 14 keywords plus
    // `[RFC#### §X.Y ¶N]` citations in test names so failures point an
    // auditor straight at the offending requirement. See
    // `tests/conformance/README.md` for the full grammar.
    //
    // The conformance binary is its own `addTest` invocation so we can
    // expose a narrower `zig build conformance` entry point and so a
    // `-Dconformance-filter='RFC9000 §17'` invocation only walks the
    // conformance corpus. It uses the default Zig test runner so we
    // don't take on a third-party runner dependency.
    //
    // The Zig default runner doesn't accept `--test-filter` at runtime
    // — filtering is a compile-time `--test-filter` flag wired via
    // `TestOptions.filters`. That is fine for our use case (auditors
    // run `zig build conformance` against a fresh tree).
    const conformance_filter = b.option(
        []const u8,
        "conformance-filter",
        "Substring filter for the RFC conformance suite (e.g. 'RFC9000 §17')",
    );
    const conformance_filters: []const []const u8 =
        if (conformance_filter) |f| &.{f} else &.{};
    const conformance_mod = b.createModule(.{
        // Lives at tests/conformance.zig (sibling of tests/root.zig)
        // so the package boundary is tests/. Suites that need the
        // existing tests/data/test_cert.pem fixture for Server-level
        // assertions can `@embedFile("../data/test_cert.pem")`.
        .root_source_file = b.path("tests/conformance.zig"),
        .target = target,
        .optimize = optimize,
    });
    conformance_mod.addImport("quic_zig", quic_zig_mod);
    conformance_mod.addImport("boringssl", boringssl_mod);
    const conformance_tests = b.addTest(.{
        .root_module = conformance_mod,
        .filters = conformance_filters,
    });
    const run_conformance_tests = b.addRunArtifact(conformance_tests);
    test_step.dependOn(&run_conformance_tests.step);

    const conformance_step = b.step("conformance", "Run quic_zig RFC-traceable conformance suites");
    conformance_step.dependOn(&run_conformance_tests.step);

    const qns_mod = b.createModule(.{
        .root_source_file = b.path("interop/qns_endpoint.zig"),
        .target = target,
        .optimize = optimize,
    });
    qns_mod.addImport("quic_zig", quic_zig_mod);
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

    // Reference embedder for the alternative-server-address receive
    // surface. Builds as both a runnable example
    // (`zig build examples`) and a test target
    // (`zig build test` walks its inline tests via `test_step`).
    const alt_addr_example_mod = b.createModule(.{
        .root_source_file = b.path("examples/alt_addr_embedder.zig"),
        .target = target,
        .optimize = optimize,
    });
    alt_addr_example_mod.addImport("quic_zig", quic_zig_mod);
    alt_addr_example_mod.addImport("boringssl", boringssl_mod);

    const alt_addr_example_exe = b.addExecutable(.{
        .name = "alt-addr-embedder-example",
        .root_module = alt_addr_example_mod,
    });
    const alt_addr_example_install = b.addInstallArtifact(alt_addr_example_exe, .{});

    const alt_addr_example_tests = b.addTest(.{ .root_module = alt_addr_example_mod });
    const run_alt_addr_example_tests = b.addRunArtifact(alt_addr_example_tests);
    test_step.dependOn(&run_alt_addr_example_tests.step);

    const examples_step = b.step("examples", "Build the embedder example programs");
    examples_step.dependOn(&alt_addr_example_install.step);

    const interop_tool_mod = b.createModule(.{
        .root_source_file = b.path("tools/external_interop.zig"),
        .target = target,
        .optimize = optimize,
    });
    const interop_tool_exe = b.addExecutable(.{
        .name = "quic-zig-external-interop",
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

    // Microbenchmarks. Built with ReleaseSafe by default, regardless
    // of the user's -Doptimize choice for the rest of the tree. This
    // keeps benchmark fixtures aligned with the production safety
    // policy while still avoiding Debug-mode noise.
    //
    // Opt into ReleaseFast only with an explicit unsafe flag, since
    // that mode disables runtime safety checks on parser surfaces.
    const bench_unsafe_release_fast = b.option(
        bool,
        "bench-unsafe-release-fast",
        "Build benchmarks with ReleaseFast instead of the default ReleaseSafe; disables runtime safety checks",
    ) orelse false;
    const bench_optimize: std.builtin.OptimizeMode = if (bench_unsafe_release_fast)
        .ReleaseFast
    else
        .ReleaseSafe;
    const bench_boringssl_dep = b.dependency("boringssl_zig", .{
        .target = target,
        .optimize = bench_optimize,
    });
    const bench_boringssl_mod = bench_boringssl_dep.module("boringssl");

    const bench_quic_zig_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_quic_zig_mod.addImport("boringssl", bench_boringssl_mod);

    const bench_mod = b.createModule(.{
        .root_source_file = b.path("bench/main.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_mod.addImport("quic_zig", bench_quic_zig_mod);
    bench_mod.addImport("boringssl", bench_boringssl_mod);

    const bench_exe = b.addExecutable(.{
        .name = "quic-zig-bench",
        .root_module = bench_mod,
    });
    const run_bench = b.addRunArtifact(bench_exe);
    if (b.args) |args| run_bench.addArgs(args);
    const bench_step = b.step("bench", "Run quic_zig microbenchmarks");
    bench_step.dependOn(&run_bench.step);

    const bench_tests_mod = b.createModule(.{
        .root_source_file = b.path("bench/root.zig"),
        .target = target,
        .optimize = bench_optimize,
    });
    bench_tests_mod.addImport("quic_zig", bench_quic_zig_mod);
    bench_tests_mod.addImport("boringssl", bench_boringssl_mod);
    const bench_tests = b.addTest(.{ .root_module = bench_tests_mod });
    const run_bench_tests = b.addRunArtifact(bench_tests);
    test_step.dependOn(&run_bench_tests.step);

    const bench_test_step = b.step("bench-test", "Run benchmark helper fixture tests");
    bench_test_step.dependOn(&run_bench_tests.step);

    // Coverage-guided fuzzing of the wire / frame / server
    // header-peek parsers. The `std.testing.fuzz` callbacks in
    // `src/wire/varint.zig`, `src/wire/header.zig`,
    // `src/frame/decode.zig`, and `src/server.zig` execute once each
    // with empty input under plain `zig build test`, so the harness
    // setup is exercised on every CI run.
    //
    // To run real coverage-guided fuzzing, use the build-system flag:
    //
    //     zig build test --fuzz=100K     # 100k iterations
    //     zig build test --fuzz          # forever (until Ctrl-C); also boots a web UI
    //
    // The flag tells Zig to rebuild the test binary with `-ffuzz`,
    // discover every `std.testing.fuzz` site, and drive each through
    // libFuzzer-equivalent coverage feedback. Crashes are minimized
    // and saved to `.zig-cache/v/`.

    // Parallel fuzz step.
    //
    // `zig build test --fuzz=10M` only saturates one CPU core: the
    // 0.17 build runner hard-codes `n_instances = 1` for limit-mode
    // fuzzing (see `std/Build/Step/Run.zig` ~line 2057, tracked
    // upstream as ziglang/zig#25352). When that lands the workaround
    // here becomes obsolete and this whole block can be deleted.
    //
    // Until then we expose every `std.testing.fuzz` site as its own
    // `addTest` filtered to that single test name. Each filtered
    // binary links against the same `quic_zig_mod`, so Zig's compile
    // cache shares the underlying object across all link steps —
    // only linking is repeated. Running them under `-j` then gives
    // real parallelism:
    //
    //     zig build fuzz --fuzz=10M -j8   # 8 fuzzers in parallel
    //     zig build fuzz --fuzz           # forever (until Ctrl-C)
    //
    // Each test runs in its own binary, so `-j<N>` is the throttle
    // for how many cores are saturated. With no `--fuzz` flag each
    // binary just runs once for a smoke check (about one fuzz
    // iteration per site), which is what CI uses to confirm the
    // harness still compiles and the seed input is well-formed.
    //
    // The existing `zig build test` still includes every fuzz test
    // in the single `unit_tests` binary; this step is purely
    // additive.
    const FuzzTarget = struct { label: []const u8, filter: []const u8 };
    const fuzz_targets = [_]FuzzTarget{
        .{ .label = "varint", .filter = "fuzz: varint decode/encode round-trip" },
        .{ .label = "header", .filter = "fuzz: header parse never panics and reports consistent offsets" },
        .{ .label = "header-roundtrip", .filter = "fuzz: header encode/parse canonical round-trip" },
        .{ .label = "long-packet", .filter = "fuzz: coalesced long-header walker terminates with bounded advance" },
        .{ .label = "packet-number", .filter = "fuzz: packet_number decode §A.3 invariants" },
        .{ .label = "protection-hp", .filter = "fuzz: protection.aesHpMask determinism and sensitivity" },
        .{ .label = "ack-range-iter", .filter = "fuzz: ack_range Iterator descending invariants" },
        .{ .label = "frame-single", .filter = "fuzz: frame decode single-frame property" },
        .{ .label = "frame-loop", .filter = "fuzz: frame decode loop until exhausted" },
        .{ .label = "frame-roundtrip", .filter = "fuzz: frame encode/decode canonical round-trip" },
        .{ .label = "server-peek-long", .filter = "fuzz: peekLongHeaderIds never panics" },
        .{ .label = "server-is-initial", .filter = "fuzz: isInitialLongHeader never panics" },
        .{ .label = "server-peek-dcid", .filter = "fuzz: peekDcidForServer never panics across all CID lengths" },
        .{ .label = "transport-params", .filter = "fuzz: transport_params decode never panics and respects RFC bounds" },
        .{ .label = "transport-params-roundtrip", .filter = "fuzz: transport_params canonical round-trip" },
        .{ .label = "path-validator", .filter = "fuzz: path_validator state-machine invariants" },
        .{ .label = "flow-control", .filter = "fuzz: flow_control ConnectionData state-machine invariants" },
        .{ .label = "send-stream", .filter = "fuzz: send_stream lifecycle invariants" },
        .{ .label = "retry-token", .filter = "fuzz: retry_token validate never panics" },
        .{ .label = "new-token", .filter = "fuzz: new_token validate never panics" },
        .{ .label = "ack-tracker", .filter = "fuzz: ack_tracker range-list invariants" },
        .{ .label = "recv-stream", .filter = "fuzz: recv_stream reassembly invariants" },
        .{ .label = "recv-stream-shuffled", .filter = "fuzz: recv_stream shuffled-delivery byte-equal reassembly" },
        .{ .label = "loss-recovery", .filter = "fuzz: loss_recovery processAck invariants" },
        .{ .label = "stateless-reset", .filter = "fuzz: stateless_reset derive determinism and uniqueness" },
        .{ .label = "anti-replay", .filter = "fuzz: anti_replay tracker invariants" },
        .{ .label = "conn-crypto", .filter = "fuzz: Connection.handleCrypto reassembly invariants" },
        .{ .label = "conn-stream", .filter = "fuzz: Connection.handleStream reassembly invariants" },
        .{ .label = "conn-migration", .filter = "fuzz: Connection.recordAuthenticatedDatagramAddress migration sequences" },
        .{ .label = "conn-cid-lifecycle", .filter = "fuzz: Connection NEW_CONNECTION_ID / RETIRE_CONNECTION_ID lifecycle invariants" },
        .{ .label = "conn-path-challenge", .filter = "fuzz: Connection PATH_CHALLENGE / PATH_RESPONSE handler invariants" },
        .{ .label = "conn-flow-window", .filter = "fuzz: Connection MAX_DATA / MAX_STREAM_DATA / MAX_STREAMS monotonicity" },
        .{ .label = "conn-blocked-frames", .filter = "fuzz: Connection DATA_BLOCKED / STREAM_DATA_BLOCKED / STREAMS_BLOCKED invariants" },
        .{ .label = "conn-close-pre-handshake", .filter = "fuzz: Connection CONNECTION_CLOSE pre-handshake envelope invariants" },
    };

    const fuzz_step = b.step(
        "fuzz",
        "Run each std.testing.fuzz site in its own binary so -j<N> parallelises limit-mode fuzzing",
    );

    for (fuzz_targets) |t| {
        const tst = b.addTest(.{
            .name = b.fmt("fuzz-{s}", .{t.label}),
            .root_module = quic_zig_mod,
            .filters = &.{t.filter},
        });
        const run_tst = b.addRunArtifact(tst);
        if (b.args) |args| run_tst.addArgs(args);
        fuzz_step.dependOn(&run_tst.step);
    }
}
