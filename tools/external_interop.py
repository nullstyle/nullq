#!/usr/bin/env python3
"""Build and run nullq's external QUIC interop gate.

This wraps the official quic-interop-runner without mutating its checkout:
the script copies the runner to a local overlay directory, injects a
server-side `nullq` implementation entry, and runs the selected peer matrix.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
WORKSPACE = REPO.parent
DEFAULT_IMAGE = "nullq-interop:local"
DEFAULT_RUNNER = WORKSPACE / "quic-interop-runner"
OVERLAY = REPO / ".zig-cache" / "interop-runner-overlay"
DOCKER_CONTEXT = REPO / ".zig-cache" / "interop-docker-context"

CASE_ALIASES = {
    "H": "handshake",
    "D": "transfer",
    "C": "chacha20",
    "S": "retry",
    "R": "resumption",
    "Z": "zerortt",
    "M": "multiplexing",
}
CASE_PRESETS = {
    "core": ["H", "D", "C", "R", "Z", "M"],
    "core+retry": ["H", "D", "C", "S", "R", "Z", "M"],
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--image", default=DEFAULT_IMAGE, help="Docker image tag for nullq's QNS endpoint")
    common.add_argument("--dry-run", action="store_true", help="print commands without executing them")

    sub.add_parser("preflight", parents=[common], help="check local tool and path availability")

    build = sub.add_parser("build-image", parents=[common], help="build the nullq QNS endpoint image")
    build.add_argument("--zig-version", default="0.16.0", help="Zig version used inside Docker")

    runner = sub.add_parser("runner", parents=[common], help="run the official quic-interop-runner gate")
    runner.add_argument("--runner-dir", type=Path, default=DEFAULT_RUNNER, help="quic-interop-runner checkout")
    runner.add_argument("--clients", default="quic-go,ngtcp2,quiche", help="comma-separated external clients")
    runner.add_argument(
        "--tests",
        default="core+retry",
        help="case preset, abbreviations, or official names; default: core+retry",
    )
    runner.add_argument("--log-dir", type=Path, default=REPO / "interop" / "logs", help="runner log directory")
    runner.add_argument("--json", type=Path, default=REPO / "interop" / "results" / "nullq-server.json", help="matrix JSON output")
    runner.add_argument("--build-image", action="store_true", help="build the image before running the matrix")

    args = parser.parse_args()
    if args.command == "preflight":
        return preflight(args)
    if args.command == "build-image":
        return build_image(args)
    if args.command == "runner":
        if args.build_image:
            rc = build_image(args)
            if rc != 0:
                return rc
        return run_runner(args)
    raise AssertionError(args.command)


def preflight(args: argparse.Namespace) -> int:
    missing = []
    for tool in ("zig", "docker", "python3"):
        if shutil.which(tool) is None:
            missing.append(tool)
    for path in (WORKSPACE / "boringssl-zig", REPO / "interop" / "qns" / "Dockerfile"):
        if not path.exists():
            missing.append(str(path))
    if missing:
        for item in missing:
            print(f"missing: {item}", file=sys.stderr)
        return 1
    print(f"tools ok; nullq image tag will be {args.image}")
    return 0


def build_image(args: argparse.Namespace) -> int:
    rc = preflight(args)
    if rc != 0:
        return rc
    stage_docker_context()
    cmd = [
        "docker",
        "build",
        "--build-arg",
        f"ZIG_VERSION={getattr(args, 'zig_version', '0.16.0')}",
        "-f",
        "nullq/interop/qns/Dockerfile",
        "-t",
        args.image,
        ".",
    ]
    return run(cmd, cwd=DOCKER_CONTEXT, dry=args.dry_run)


def run_runner(args: argparse.Namespace) -> int:
    if not args.runner_dir.exists():
        print(
            f"missing quic-interop-runner checkout: {args.runner_dir}\n"
            "clone https://github.com/quic-interop/quic-interop-runner next to nullq or pass --runner-dir",
            file=sys.stderr,
        )
        return 1
    overlay = prepare_runner_overlay(args.runner_dir, args.image)
    tests = expand_cases(args.tests)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    args.json.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        "python3",
        "run.py",
        "-s",
        "nullq",
        "-c",
        args.clients,
        "-t",
        ",".join(tests),
        "-l",
        str(args.log_dir.resolve()),
        "-j",
        str(args.json.resolve()),
        "-m",
        "-i",
        "nullq",
    ]
    return run(cmd, cwd=overlay, dry=args.dry_run)


def stage_docker_context() -> None:
    if DOCKER_CONTEXT.exists():
        shutil.rmtree(DOCKER_CONTEXT)
    DOCKER_CONTEXT.mkdir(parents=True)
    copy_tree(REPO, DOCKER_CONTEXT / "nullq")
    copy_tree(WORKSPACE / "boringssl-zig", DOCKER_CONTEXT / "boringssl-zig")


def copy_tree(src: Path, dst: Path) -> None:
    ignore = shutil.ignore_patterns(
        ".git",
        ".zig-cache",
        "zig-cache",
        "zig-out",
        "__pycache__",
        "*.pyc",
        "interop/logs",
        "interop/results",
    )
    shutil.copytree(src, dst, ignore=ignore)


def prepare_runner_overlay(runner_dir: Path, image: str) -> Path:
    if OVERLAY.exists():
        shutil.rmtree(OVERLAY)
    copy_tree(runner_dir.resolve(), OVERLAY)
    impl_file = OVERLAY / "implementations_quic.json"
    data = json.loads(impl_file.read_text())
    data["nullq"] = {
        "image": image,
        "url": "https://github.com/nullstyle/nullq",
        "role": "server",
    }
    impl_file.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return OVERLAY


def expand_cases(spec: str) -> list[str]:
    parts = CASE_PRESETS.get(spec, spec.split(","))
    expanded = []
    for part in parts:
        item = part.strip()
        if not item:
            continue
        expanded.append(CASE_ALIASES.get(item.upper(), item))
    return expanded


def run(cmd: list[str], cwd: Path, dry: bool) -> int:
    print("+ " + " ".join(cmd))
    if dry:
        return 0
    return subprocess.run(cmd, cwd=cwd).returncode


if __name__ == "__main__":
    raise SystemExit(main())
