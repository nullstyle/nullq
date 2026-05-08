FROM martenseemann/quic-network-simulator-endpoint:latest AS build

ARG TARGETPLATFORM
ARG ZIG_VERSION=0.16.0

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl xz-utils cmake ninja-build clang git python3 perl \
    && rm -rf /var/lib/apt/lists/*

RUN case "$TARGETPLATFORM" in \
        "linux/arm64") zig_arch="aarch64-linux" ;; \
        *) zig_arch="x86_64-linux" ;; \
    esac \
    && curl -fsSL "https://ziglang.org/download/${ZIG_VERSION}/zig-${zig_arch}-${ZIG_VERSION}.tar.xz" -o /tmp/zig.tar.xz \
    && mkdir -p /opt/zig \
    && tar -xJf /tmp/zig.tar.xz -C /opt/zig --strip-components=1 \
    && rm /tmp/zig.tar.xz

ENV PATH="/opt/zig:${PATH}"

COPY quic-zig /src/quic-zig
COPY boringssl-zig /src/boringssl-zig

WORKDIR /src/quic-zig
RUN zig build qns-endpoint -Doptimize=ReleaseSafe

FROM martenseemann/quic-network-simulator-endpoint:latest

WORKDIR /
COPY --from=build /src/quic-zig/zig-out/bin/qns-endpoint /qns-endpoint
COPY quic-zig/interop/qns/run_endpoint.sh /run_endpoint.sh
RUN chmod +x /run_endpoint.sh

ENTRYPOINT ["/run_endpoint.sh"]
