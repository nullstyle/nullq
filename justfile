set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

check-tools:
    @command -v zig >/dev/null || { echo "missing zig"; exit 1; }
    @echo "tools ok: $(zig version)"

# Run the full nullq test suite (currently: smoke).
test:
    zig build test

# Run coverage-guided fuzzing in parallel (one binary per fuzz site).
fuzz:
    zig build fuzz --fuzz=10M -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

clean:
    rm -rf .zig-cache zig-out
