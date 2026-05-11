set shell := ["bash", "-euo", "pipefail", "-c"]

qns_image := env_var_or_default("QUIC_ZIG_IMAGE", "quic-zig-qns:local")
runner_dir := env_var_or_default("RUNNER_DIR", "../quic-interop-runner")
interop_clients := env_var_or_default("CLIENTS", "quic-go,ngtcp2,quiche")
interop_servers := env_var_or_default("SERVERS", "quic-go,ngtcp2,quiche")
interop_tests := env_var_or_default("TESTS", "H,D")
remote_host := env_var_or_default("REMOTE_HOST", "root@quic-zig-interop")
remote_dir := env_var_or_default("REMOTE_DIR", "/root/quic-interop-runner")
remote_python := env_var_or_default("REMOTE_PYTHON", "/root/quic-interop-runner/.venv/bin/python3")
remote_image := env_var_or_default("REMOTE_IMAGE", "ghcr.io/nullstyle/quic-zig-qns:latest")
mainstream_impls := env_var_or_default("MAINSTREAM_IMPLS", "quic-go,ngtcp2,quiche,picoquic,aioquic,msquic,neqo,quinn,s2n-quic,lsquic,xquic")
feature_clients := env_var_or_default("FEATURE_CLIENTS", "quic-go,ngtcp2,quiche")
feature_tests := env_var_or_default("FEATURE_TESTS", "handshake,transfer,chacha20,retry,resumption,zerortt,multiplexing,keyupdate,longrtt")

default:
    @just --list

check-tools:
    @command -v zig >/dev/null || { echo "missing zig"; exit 1; }
    @echo "tools ok: $(zig version)"

# Run the full quic-zig test suite (currently: smoke).
test:
    zig build test

# Run coverage-guided fuzzing in parallel (one binary per fuzz site).
fuzz:
    zig build fuzz --fuzz=10M -j$(nproc 2>/dev/null || sysctl -n hw.ncpu)

clean:
    rm -rf .zig-cache zig-out

# Build the local QNS image from this checkout.
interop-build-image:
    zig build external-interop -- build-image --image "{{qns_image}}"

# Run quic-zig as a QNS server against external clients.
interop:
    zig build external-interop -- runner --role server --runner-dir "{{runner_dir}}" --image "{{qns_image}}" --clients "{{interop_clients}}" --tests "{{interop_tests}}"

# Run quic-zig as a QNS client against external servers.
interop-client:
    zig build external-interop -- runner --role client --runner-dir "{{runner_dir}}" --image "{{qns_image}}" --servers "{{interop_servers}}" --tests "{{interop_tests}}"

interop-both: interop interop-client

interop-features:
    CLIENTS=quic-go TESTS=H,D,C,S,R,Z,M just interop

interop-loss:
    CLIENTS=quic-go TESTS=loss just interop

interop-loss-client:
    SERVERS=quic-go TESTS=transferloss,blackhole just interop-client

interop-loss-both: interop-loss interop-loss-client

# Refresh and inspect the published QNS image on a remote runner host.
interop-remote-pull:
    ssh "{{remote_host}}" 'docker pull {{remote_image}}'
    ssh "{{remote_host}}" 'docker image inspect {{remote_image}} >/dev/null'

interop-remote-mainstream: interop-remote-pull
    ssh -t "{{remote_host}}" 'cd {{remote_dir}} && {{remote_python}} run.py -i quic-zig -s {{mainstream_impls}} -c {{mainstream_impls}} -t handshake,transfer'

interop-remote-features: interop-remote-pull
    ssh -t "{{remote_host}}" 'cd {{remote_dir}} && {{remote_python}} run.py -s quic-zig -c {{feature_clients}} -t {{feature_tests}}'

interop-remote-matrix: interop-remote-pull
    ssh -t "{{remote_host}}" 'cd {{remote_dir}} && {{remote_python}} run.py -i quic-zig -j /tmp/quic-zig-matrix.json -l logs/quic-zig-full-matrix'
