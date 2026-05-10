FROM martenseemann/quic-network-simulator-endpoint:latest AS build

ARG TARGETPLATFORM
# Pinned to a 0.17.0-dev master tarball because mise.toml tracks Zig master
# and HEAD uses 0.17-only forms; tagged 0.16.0 is no longer ABI-compatible.
# Dev tarballs live under /builds/ (no per-version subdirectory), unlike
# tagged releases which are served from /download/<version>/.
ARG ZIG_VERSION=0.17.0-dev.269+ebff43698

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils cmake ninja-build clang git python3 perl \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETPLATFORM" in \
        "linux/arm64") zig_arch="aarch64-linux" ;; \
        *) zig_arch="x86_64-linux" ;; \
    esac \
    && curl -fsSL "https://ziglang.org/builds/zig-${zig_arch}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
    && mkdir -p /opt/zig \
    && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
    && rm /tmp/zig.tar.xz

ENV PATH="/opt/zig:${PATH}"

COPY quic-zig /src/quic-zig
COPY boringssl-zig /src/boringssl-zig

# Pre-populate the zig package cache from the host's
# ~/.cache/zig/p/ if the wrapper staged it. Without this, the build
# step below tries to fetch boringssl-zig over HTTPS from
# github.com — which is flaky enough during interop iteration that
# transient `HttpConnectionClosing` errors abort the matrix run.
# When the staged cache is absent (e.g. fresh checkout), zig falls
# back to the URL fetch.
COPY zig-cache-p* /root/.cache/zig/p/

WORKDIR /src/quic-zig
RUN zig build qns-endpoint -Doptimize=ReleaseSafe

FROM martenseemann/quic-network-simulator-endpoint:latest

WORKDIR /
COPY --from=build /src/quic-zig/zig-out/bin/qns-endpoint /qns-endpoint
COPY quic-zig/interop/qns/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
