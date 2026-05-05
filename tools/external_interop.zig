const std = @import("std");

const default_image = "nullq-interop:local";
const default_zig_version = "0.16.0";
const default_runner_python = "3.12";
const default_wireshark_image = "nullq-interop-wireshark:local";

const case_aliases = [_]CaseAlias{
    .{ .short = "H", .long = "handshake" },
    .{ .short = "D", .long = "transfer" },
    .{ .short = "C", .long = "chacha20" },
    .{ .short = "S", .long = "retry" },
    .{ .short = "R", .long = "resumption" },
    .{ .short = "Z", .long = "zerortt" },
    .{ .short = "M", .long = "multiplexing" },
};

const CaseAlias = struct {
    short: []const u8,
    long: []const u8,
};

const Config = struct {
    repo: []const u8,
    workspace: []const u8,
    path_env: []const u8 = "",
    image: []const u8 = default_image,
    zig_version: []const u8 = default_zig_version,
    dry_run: bool = false,
    runner_dir: ?[]const u8 = null,
    role: RunnerRole = .server,
    clients: []const u8 = "quic-go,ngtcp2,quiche",
    servers: []const u8 = "quic-go,ngtcp2,quiche",
    tests: []const u8 = "core+retry",
    runner_python: []const u8 = default_runner_python,
    wireshark_image: []const u8 = default_wireshark_image,
    log_dir: ?[]const u8 = null,
    json_path: ?[]const u8 = null,
    build_image: bool = false,
};

const RunnerRole = enum {
    server,
    client,
};

pub fn main(init: std.process.Init) !void {
    var arena = std.heap.ArenaAllocator.init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = init.io;

    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);

    const repo = cwd;
    const workspace = std.fs.path.dirname(repo) orelse ".";
    var cfg = Config{
        .repo = repo,
        .workspace = workspace,
        .path_env = init.environ_map.get("PATH") orelse "",
    };

    var args = try std.process.Args.Iterator.initAllocator(init.minimal.args, allocator);
    defer args.deinit();
    _ = args.next();

    const command = args.next() orelse {
        usage();
        std.process.exit(1);
    };
    var rest: std.ArrayList([]const u8) = .empty;
    defer rest.deinit(allocator);
    while (args.next()) |arg| try rest.append(allocator, arg);

    if (std.mem.eql(u8, command, "preflight")) {
        try parsePreflight(rest.items, &cfg);
        try preflight(allocator, io, cfg, false);
        return;
    }
    if (std.mem.eql(u8, command, "build-image")) {
        try parseBuildImage(rest.items, &cfg);
        try buildImage(allocator, io, cfg);
        return;
    }
    if (std.mem.eql(u8, command, "runner")) {
        try parseRunner(allocator, rest.items, &cfg);
        if (cfg.build_image) try buildImage(allocator, io, cfg);
        try runRunner(allocator, io, cfg);
        return;
    }

    usage();
    std.debug.print("unknown command: {s}\n", .{command});
    std.process.exit(1);
}

fn usage() void {
    std.debug.print(
        \\usage:
        \\  zig build external-interop -- preflight [--image nullq-interop:local] [--dry-run]
        \\  zig build external-interop -- build-image [--image nullq-interop:local] [--zig-version 0.16.0] [--dry-run]
        \\  zig build external-interop -- runner [--role server|client] [--build-image] [--runner-dir ../quic-interop-runner] [--clients quic-go,ngtcp2,quiche] [--servers quic-go,ngtcp2,quiche] [--tests core+retry] [--python 3.12] [--wireshark-image nullq-interop-wireshark:local] [--dry-run]
        \\
    , .{});
}

fn parsePreflight(args: []const []const u8, cfg: *Config) !void {
    var i: usize = 0;
    while (i < args.len) {
        if (try parseCommonAt(args, &i, cfg)) continue;
        std.debug.print("unknown preflight argument: {s}\n", .{args[i]});
        return error.UnknownArgument;
    }
}

fn parseBuildImage(args: []const []const u8, cfg: *Config) !void {
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (try parseCommonAt(args, &i, cfg)) continue;
        if (std.mem.eql(u8, arg, "--zig-version")) {
            i += 1;
            if (i >= args.len) return error.MissingZigVersion;
            cfg.zig_version = args[i];
            i += 1;
        } else {
            std.debug.print("unknown build-image argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
}

fn parseRunner(allocator: std.mem.Allocator, args: []const []const u8, cfg: *Config) !void {
    var i: usize = 0;
    while (i < args.len) {
        const arg = args[i];
        if (try parseCommonAt(args, &i, cfg)) continue;
        if (std.mem.eql(u8, arg, "--runner-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingRunnerDir;
            cfg.runner_dir = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--role")) {
            i += 1;
            if (i >= args.len) return error.MissingRole;
            cfg.role = parseRole(args[i]) orelse return error.InvalidRole;
            i += 1;
        } else if (std.mem.eql(u8, arg, "--clients")) {
            i += 1;
            if (i >= args.len) return error.MissingClients;
            cfg.clients = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--servers")) {
            i += 1;
            if (i >= args.len) return error.MissingServers;
            cfg.servers = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--tests")) {
            i += 1;
            if (i >= args.len) return error.MissingTests;
            cfg.tests = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--python")) {
            i += 1;
            if (i >= args.len) return error.MissingPython;
            cfg.runner_python = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--wireshark-image")) {
            i += 1;
            if (i >= args.len) return error.MissingWiresharkImage;
            cfg.wireshark_image = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--log-dir")) {
            i += 1;
            if (i >= args.len) return error.MissingLogDir;
            cfg.log_dir = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--json")) {
            i += 1;
            if (i >= args.len) return error.MissingJsonPath;
            cfg.json_path = args[i];
            i += 1;
        } else if (std.mem.eql(u8, arg, "--build-image")) {
            cfg.build_image = true;
            i += 1;
        } else {
            std.debug.print("unknown runner argument: {s}\n", .{arg});
            return error.UnknownArgument;
        }
    }
    if (cfg.runner_dir == null) {
        cfg.runner_dir = try std.fs.path.join(allocator, &.{ cfg.workspace, "quic-interop-runner" });
    }
    if (cfg.log_dir == null) {
        cfg.log_dir = try std.fs.path.join(allocator, &.{ cfg.repo, "interop", "logs" });
    }
    if (cfg.json_path == null) {
        cfg.json_path = try std.fs.path.join(allocator, &.{ cfg.repo, "interop", "results", defaultRunnerJsonName(cfg.role) });
    }
    cfg.runner_dir = try absolutePath(allocator, cfg.repo, cfg.runner_dir.?);
    cfg.log_dir = try absolutePath(allocator, cfg.repo, cfg.log_dir.?);
    cfg.json_path = try absolutePath(allocator, cfg.repo, cfg.json_path.?);
}

fn parseRole(role: []const u8) ?RunnerRole {
    if (std.ascii.eqlIgnoreCase(role, "server")) return .server;
    if (std.ascii.eqlIgnoreCase(role, "client")) return .client;
    return null;
}

fn defaultRunnerJsonName(role: RunnerRole) []const u8 {
    return switch (role) {
        .server => "nullq-server.json",
        .client => "nullq-client.json",
    };
}

fn absolutePath(allocator: std.mem.Allocator, base: []const u8, path: []const u8) ![]const u8 {
    if (std.fs.path.isAbsolute(path)) return path;
    return try std.fs.path.resolve(allocator, &.{ base, path });
}

fn parseCommonAt(args: []const []const u8, i: *usize, cfg: *Config) !bool {
    const arg = args[i.*];
    if (std.mem.eql(u8, arg, "--image")) {
        i.* += 1;
        if (i.* >= args.len) return error.MissingImage;
        cfg.image = args[i.*];
        i.* += 1;
        return true;
    }
    if (std.mem.eql(u8, arg, "--dry-run")) {
        cfg.dry_run = true;
        i.* += 1;
        return true;
    }
    return false;
}

fn preflight(allocator: std.mem.Allocator, io: std.Io, cfg: Config, runner: bool) !void {
    try expectPath(allocator, io, try std.fs.path.join(allocator, &.{ cfg.workspace, "boringssl-zig" }));
    try expectPath(allocator, io, try std.fs.path.join(allocator, &.{ cfg.repo, "interop", "qns", "Dockerfile" }));

    if (!cfg.dry_run) {
        try runAndRequireZero(allocator, io, &.{ "docker", "--version" }, null);
        if (runner) {
            try runAndRequireZero(allocator, io, &.{ "uv", "--version" }, null);
        }
    }
    std.debug.print("tools ok; nullq image tag will be {s}\n", .{cfg.image});
}

fn buildImage(allocator: std.mem.Allocator, io: std.Io, cfg: Config) !void {
    try preflight(allocator, io, cfg, false);
    const docker_context = try std.fs.path.join(allocator, &.{ cfg.repo, ".zig-cache", "interop-docker-context" });
    try recreateDir(io, docker_context);

    const staged_nullq = try std.fs.path.join(allocator, &.{ docker_context, "nullq" });
    const staged_boringssl = try std.fs.path.join(allocator, &.{ docker_context, "boringssl-zig" });
    try copyTree(allocator, io, cfg.repo, staged_nullq);
    try copyTree(allocator, io, try std.fs.path.join(allocator, &.{ cfg.workspace, "boringssl-zig" }), staged_boringssl);

    const cmd = [_][]const u8{
        "docker",
        "build",
        "--build-arg",
        try std.fmt.allocPrint(allocator, "ZIG_VERSION={s}", .{cfg.zig_version}),
        "-f",
        "nullq/interop/qns/Dockerfile",
        "-t",
        cfg.image,
        ".",
    };
    try runCommand(io, &cmd, docker_context, cfg.dry_run);
}

fn runRunner(allocator: std.mem.Allocator, io: std.Io, cfg: Config) !void {
    try preflight(allocator, io, cfg, true);
    const runner_dir = cfg.runner_dir.?;
    try expectPath(allocator, io, runner_dir);

    const overlay = try std.fs.path.join(allocator, &.{ cfg.repo, ".zig-cache", "interop-runner-overlay" });
    try recreateDir(io, overlay);
    try copyTree(allocator, io, runner_dir, overlay);
    try patchRunnerKeylogSelection(allocator, io, overlay);
    try injectNullqImplementation(allocator, io, overlay, cfg.image, @tagName(cfg.role));
    const trace_tools_dir = try prepareTraceTools(allocator, io, cfg, overlay);

    const tests = try expandCases(allocator, cfg.tests);
    defer allocator.free(tests);
    try prepareRunnerOutputs(io, cfg);

    var cmd: std.ArrayList([]const u8) = .empty;
    defer cmd.deinit(allocator);
    if (trace_tools_dir) |dir| {
        const env_path = if (cfg.path_env.len > 0)
            try std.fmt.allocPrint(allocator, "PATH={s}:{s}", .{ dir, cfg.path_env })
        else
            try std.fmt.allocPrint(allocator, "PATH={s}", .{dir});
        try cmd.appendSlice(allocator, &.{ "/usr/bin/env", env_path });
    }
    try cmd.appendSlice(allocator, &.{ "uv", "run", "--python", cfg.runner_python });
    const requirements = try std.fs.path.join(allocator, &.{ overlay, "requirements.txt" });
    if (pathExists(io, requirements)) {
        try cmd.appendSlice(allocator, &.{ "--with-requirements", "requirements.txt" });
    }
    try cmd.appendSlice(allocator, &.{
        "python",
        "run.py",
    });
    switch (cfg.role) {
        .server => try cmd.appendSlice(allocator, &.{
            "-s",
            "nullq",
            "-c",
            cfg.clients,
        }),
        .client => try cmd.appendSlice(allocator, &.{
            "-s",
            cfg.servers,
            "-c",
            "nullq",
        }),
    }
    try cmd.appendSlice(allocator, &.{
        "-t",
        tests,
        "-l",
        cfg.log_dir.?,
        "-j",
        cfg.json_path.?,
        "-m",
        "-i",
        "nullq",
    });
    try runCommand(io, cmd.items, overlay, cfg.dry_run);
}

fn prepareTraceTools(allocator: std.mem.Allocator, io: std.Io, cfg: Config, overlay: []const u8) !?[]const u8 {
    if (commandAvailable(allocator, io, cfg.path_env, "tshark") and commandAvailable(allocator, io, cfg.path_env, "editcap")) {
        return null;
    }

    std.debug.print("host tshark/editcap not found; using Docker Wireshark tools image {s}\n", .{cfg.wireshark_image});
    try ensureWiresharkImage(allocator, io, cfg);

    const bin_dir = try std.fs.path.join(allocator, &.{ overlay, ".nullq-tools-bin" });
    if (cfg.dry_run) return bin_dir;

    try std.Io.Dir.cwd().createDirPath(io, bin_dir);
    try writeDockerToolShim(allocator, io, bin_dir, "tshark", cfg);
    try writeDockerToolShim(allocator, io, bin_dir, "editcap", cfg);
    return bin_dir;
}

fn ensureWiresharkImage(allocator: std.mem.Allocator, io: std.Io, cfg: Config) !void {
    if (!cfg.dry_run and dockerImageExists(allocator, io, cfg.wireshark_image)) return;

    const dockerfile = try std.fs.path.join(allocator, &.{ cfg.repo, "interop", "qns-tools", "Dockerfile" });
    const context = try std.fs.path.join(allocator, &.{ cfg.repo, "interop", "qns-tools" });
    const cmd = [_][]const u8{
        "docker",
        "build",
        "-f",
        dockerfile,
        "-t",
        cfg.wireshark_image,
        ".",
    };
    try runCommand(io, &cmd, context, cfg.dry_run);
}

fn dockerImageExists(allocator: std.mem.Allocator, io: std.Io, image: []const u8) bool {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "docker", "image", "inspect", image },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(1024),
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn writeDockerToolShim(allocator: std.mem.Allocator, io: std.Io, bin_dir: []const u8, tool: []const u8, cfg: Config) !void {
    const path = try std.fs.path.join(allocator, &.{ bin_dir, tool });
    const script = try std.fmt.allocPrint(allocator,
        \\#!/bin/sh
        \\exec docker run --rm -i -v '{s}:{s}:rw' -v /tmp:/tmp:rw -v /private:/private:rw --entrypoint {s} {s} "$@"
        \\
    , .{ cfg.workspace, cfg.workspace, tool, cfg.wireshark_image });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = script });
    try runAndRequireZero(allocator, io, &.{ "chmod", "+x", path }, null);
}

fn commandAvailable(allocator: std.mem.Allocator, io: std.Io, path_env: []const u8, name: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, path_env, std.fs.path.delimiter);
    while (it.next()) |dir| {
        const candidate = std.fs.path.join(allocator, &.{ dir, name }) catch continue;
        defer allocator.free(candidate);
        std.Io.Dir.accessAbsolute(io, candidate, .{}) catch continue;
        return true;
    }
    return false;
}

fn recreateDir(io: std.Io, path: []const u8) !void {
    try std.Io.Dir.cwd().deleteTree(io, path);
    try std.Io.Dir.cwd().createDirPath(io, path);
}

fn prepareRunnerOutputs(io: std.Io, cfg: Config) !void {
    try ensureParentDir(io, cfg.log_dir.?);
    try ensureParentDir(io, cfg.json_path.?);
    if (cfg.dry_run) return;
    try std.Io.Dir.cwd().deleteTree(io, cfg.log_dir.?);
}

fn copyTree(allocator: std.mem.Allocator, io: std.Io, source_path: []const u8, dest_path: []const u8) !void {
    try std.Io.Dir.cwd().createDirPath(io, dest_path);
    var src = try std.Io.Dir.openDirAbsolute(io, source_path, .{ .iterate = true });
    defer src.close(io);
    var dst = try std.Io.Dir.openDirAbsolute(io, dest_path, .{});
    defer dst.close(io);

    var walker = try src.walkSelectively(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (ignoreCopyPath(entry.path)) {
            continue;
        }
        switch (entry.kind) {
            .directory => {
                try dst.createDirPath(io, entry.path);
                try walker.enter(io, entry);
            },
            .file, .sym_link => {
                try std.Io.Dir.copyFile(src, entry.path, dst, entry.path, io, .{ .make_path = true });
            },
            else => {},
        }
    }
}

fn ignoreCopyPath(path: []const u8) bool {
    const exact = [_][]const u8{
        ".git",
        ".zig-cache",
        "zig-cache",
        "zig-out",
        ".cache",
        "zig-pkg",
        "__pycache__",
        "interop/logs",
        "interop/results",
    };
    for (exact) |name| {
        if (std.mem.eql(u8, path, name)) return true;
        if (std.mem.startsWith(u8, path, name) and
            path.len > name.len and
            path[name.len] == std.fs.path.sep)
        {
            return true;
        }
    }
    if (std.mem.endsWith(u8, path, ".pyc")) return true;
    return false;
}

fn injectNullqImplementation(
    allocator: std.mem.Allocator,
    io: std.Io,
    overlay: []const u8,
    image: []const u8,
    role: []const u8,
) !void {
    const impl_path = try std.fs.path.join(allocator, &.{ overlay, "implementations_quic.json" });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, impl_path, allocator, .limited(8 * 1024 * 1024));
    defer allocator.free(bytes);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidImplementationsJson;

    var nullq = try std.json.ObjectMap.init(allocator, &.{}, &.{});
    try nullq.put(allocator, "image", .{ .string = image });
    try nullq.put(allocator, "url", .{ .string = "https://github.com/nullstyle/nullq" });
    try nullq.put(allocator, "role", .{ .string = role });
    try parsed.value.object.put(allocator, "nullq", .{ .object = nullq });

    const rendered = try std.fmt.allocPrint(allocator, "{f}\n", .{std.json.fmt(parsed.value, .{ .whitespace = .indent_2 })});
    defer allocator.free(rendered);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = impl_path, .data = rendered });
}

fn patchRunnerKeylogSelection(
    allocator: std.mem.Allocator,
    io: std.Io,
    overlay: []const u8,
) !void {
    const testcase_path = try std.fs.path.join(allocator, &.{ overlay, "testcase.py" });
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, testcase_path, allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(bytes);

    const needle =
        \\    def _keylog_file(self) -> str:
        \\        if self._is_valid_keylog(self._client_keylog_file):
        \\            logging.debug("Using the client's key log file.")
        \\            return self._client_keylog_file
        \\        elif self._is_valid_keylog(self._server_keylog_file):
        \\            logging.debug("Using the server's key log file.")
        \\            return self._server_keylog_file
        \\        logging.debug("No key log file found.")
    ;
    const replacement =
        \\    def _keylog_file(self) -> str:
        \\        client_valid = self._is_valid_keylog(self._client_keylog_file)
        \\        server_valid = self._is_valid_keylog(self._server_keylog_file)
        \\        if client_valid and server_valid:
        \\            merged = self._client_keylog_file + ".combined"
        \\            try:
        \\                if (
        \\                    not os.path.isfile(merged)
        \\                    or os.path.getmtime(merged)
        \\                    < max(
        \\                        os.path.getmtime(self._client_keylog_file),
        \\                        os.path.getmtime(self._server_keylog_file),
        \\                    )
        \\                ):
        \\                    with open(merged, "w") as out:
        \\                        with open(self._client_keylog_file, "r") as client:
        \\                            shutil.copyfileobj(client, out)
        \\                        out.write("\n")
        \\                        with open(self._server_keylog_file, "r") as server:
        \\                            shutil.copyfileobj(server, out)
        \\                logging.debug("Using combined client/server key log file.")
        \\                return merged
        \\            except OSError as e:
        \\                logging.debug("Failed to merge key log files: %s", e)
        \\        if client_valid:
        \\            logging.debug("Using the client's key log file.")
        \\            return self._client_keylog_file
        \\        elif server_valid:
        \\            logging.debug("Using the server's key log file.")
        \\            return self._server_keylog_file
        \\        logging.debug("No key log file found.")
    ;

    if (std.mem.indexOf(u8, bytes, replacement) != null) return;
    const idx = std.mem.indexOf(u8, bytes, needle) orelse return error.UnsupportedRunnerKeylogMethod;
    var patched: std.ArrayList(u8) = .empty;
    defer patched.deinit(allocator);
    try patched.appendSlice(allocator, bytes[0..idx]);
    try patched.appendSlice(allocator, replacement);
    try patched.appendSlice(allocator, bytes[idx + needle.len ..]);
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = testcase_path, .data = patched.items });
}

fn expandCases(allocator: std.mem.Allocator, spec: []const u8) ![]u8 {
    if (std.mem.eql(u8, spec, "core")) {
        return try allocator.dupe(u8, "handshake,transfer,chacha20,resumption,zerortt,multiplexing");
    }
    if (std.mem.eql(u8, spec, "core+retry")) {
        return try allocator.dupe(u8, "handshake,transfer,chacha20,retry,resumption,zerortt,multiplexing");
    }

    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.splitScalar(u8, spec, ',');
    var first = true;
    while (it.next()) |raw| {
        const item = std.mem.trim(u8, raw, " \t\r\n");
        if (item.len == 0) continue;
        if (!first) try out.append(allocator, ',');
        first = false;
        try out.appendSlice(allocator, aliasCase(item));
    }
    return try out.toOwnedSlice(allocator);
}

fn aliasCase(item: []const u8) []const u8 {
    for (case_aliases) |alias| {
        if (std.ascii.eqlIgnoreCase(item, alias.short)) return alias.long;
    }
    return item;
}

fn expectPath(allocator: std.mem.Allocator, io: std.Io, path: []const u8) !void {
    _ = allocator;
    std.Io.Dir.accessAbsolute(io, path, .{}) catch |err| {
        std.debug.print("missing: {s}\n", .{path});
        return err;
    };
}

fn pathExists(io: std.Io, path: []const u8) bool {
    std.Io.Dir.accessAbsolute(io, path, .{}) catch return false;
    return true;
}

fn ensureParentDir(io: std.Io, path: []const u8) !void {
    const parent = std.fs.path.dirname(path) orelse return;
    try std.Io.Dir.cwd().createDirPath(io, parent);
}

fn runCommand(io: std.Io, argv: []const []const u8, cwd: []const u8, dry_run: bool) !void {
    printCommand(argv);
    if (dry_run) return;
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .path = cwd },
        .stdin = .inherit,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) std.process.exit(code),
        .signal, .stopped, .unknown => std.process.exit(1),
    }
}

fn runAndRequireZero(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8, cwd: ?[]const u8) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .cwd = if (cwd) |path| .{ .path = path } else .inherit,
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    std.debug.print("command failed: ", .{});
    printCommand(argv);
    if (result.stderr.len > 0) std.debug.print("{s}\n", .{result.stderr});
    return error.CommandFailed;
}

fn printCommand(argv: []const []const u8) void {
    std.debug.print("+", .{});
    for (argv) |arg| std.debug.print(" {s}", .{arg});
    std.debug.print("\n", .{});
}

test "case expansion supports presets and aliases" {
    const allocator = std.testing.allocator;
    const core = try expandCases(allocator, "H,D,C");
    defer allocator.free(core);
    try std.testing.expectEqualStrings("handshake,transfer,chacha20", core);

    const preset = try expandCases(allocator, "core+retry");
    defer allocator.free(preset);
    try std.testing.expect(std.mem.indexOf(u8, preset, "retry") != null);
}

test "runner paths are normalized to absolute paths" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .repo = "/tmp/nullq",
        .workspace = "/tmp",
    };
    const args = [_][]const u8{
        "--runner-dir",
        "../quic-interop-runner",
        "--log-dir",
        "interop/logs",
        "--json",
        "interop/results/out.json",
    };
    try parseRunner(allocator, &args, &cfg);
    defer allocator.free(cfg.runner_dir.?);
    defer allocator.free(cfg.log_dir.?);
    defer allocator.free(cfg.json_path.?);

    try std.testing.expect(std.fs.path.isAbsolute(cfg.runner_dir.?));
    try std.testing.expect(std.fs.path.isAbsolute(cfg.log_dir.?));
    try std.testing.expect(std.fs.path.isAbsolute(cfg.json_path.?));
    try std.testing.expect(std.mem.endsWith(u8, cfg.runner_dir.?, "quic-interop-runner"));
    try std.testing.expect(std.mem.endsWith(u8, cfg.log_dir.?, "interop/logs"));
    try std.testing.expect(std.mem.endsWith(u8, cfg.json_path.?, "interop/results/out.json"));
}

test "runner client role defaults to client result path" {
    const allocator = std.testing.allocator;
    var cfg = Config{
        .repo = "/tmp/nullq",
        .workspace = "/tmp",
    };
    const args = [_][]const u8{
        "--role",
        "client",
        "--servers",
        "quic-go",
    };
    try parseRunner(allocator, &args, &cfg);
    defer allocator.free(cfg.runner_dir.?);
    defer allocator.free(cfg.log_dir.?);
    defer allocator.free(cfg.json_path.?);

    try std.testing.expectEqual(RunnerRole.client, cfg.role);
    try std.testing.expectEqualStrings("quic-go", cfg.servers);
    try std.testing.expect(std.mem.endsWith(u8, cfg.json_path.?, "interop/results/nullq-client.json"));
}

test "copy ignore filters generated trees" {
    try std.testing.expect(ignoreCopyPath(".git"));
    try std.testing.expect(ignoreCopyPath(".zig-cache/foo"));
    try std.testing.expect(ignoreCopyPath("interop/logs/output.txt"));
    try std.testing.expect(ignoreCopyPath("tools/__pycache__/x.pyc"));
    try std.testing.expect(!ignoreCopyPath("interop/qns/Dockerfile"));
}
