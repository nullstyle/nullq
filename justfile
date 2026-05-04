set shell := ["bash", "-euo", "pipefail", "-c"]

default:
    @just --list

check-tools:
    @command -v zig >/dev/null || { echo "missing zig"; exit 1; }
    @echo "tools ok: $(zig version)"

# Run the full nullq test suite (currently: smoke).
test:
    zig build test

clean:
    rm -rf .zig-cache zig-out
