#!/bin/sh
set -eu

/setup.sh

case "${TESTCASE:-}" in
  ""|handshake|transfer|longrtt|chacha20|multiplexing|retry|resumption|zerortt|keyupdate|blackhole|handshakeloss|transferloss|handshakecorruption|transfercorruption|multiconnect|connectionmigration|amplificationlimit|ipv6|rebind-addr|rebind-port|crosstraffic|versionnegotiation|goodput|throughput|v2)
    # Most testcase names are runner-side hints (the runner injects
    # the named network simulator profile and validates outcomes
    # from the qlog / pcap); the qns endpoint's behaviour is
    # generic. Three exceptions are still routed by the wrapper:
    #   - retry            → adds the server `-retry` flag below.
    #   - connectionmigration → handled inside the binary via the
    #                       `server46` hostname heuristic at
    #                       `qns_endpoint.zig:921`.
    #   - keyupdate        → currently client-side only via
    #                       `ClientConnectionOptions.request_key_update`;
    #                       server-side latch is a known gap.
    ;;
  preferredaddress|http3)
    # preferredaddress: server-side `preferred_address` advertise
    #   wiring is a known gap in `qns_endpoint.zig` (the codec is
    #   present in `src/tls/transport_params.zig`).
    # http3: out of scope — quic-zig is transport-only and the
    #   qns endpoint speaks the `hq-interop` HTTP/0.9 ALPN.
    echo "quic-zig qns endpoint does not yet support TESTCASE=${TESTCASE}" >&2
    exit 127
    ;;
  *)
    echo "quic-zig qns endpoint does not recognize TESTCASE=${TESTCASE:-unset}" >&2
    exit 127
    ;;
esac

case "${ROLE:-server}" in
  server)
    retry_arg=""
    if [ "${TESTCASE:-}" = "retry" ]; then
      retry_arg="-retry"
    fi
    # Inherit the binary's dual-stack default (`[::]:443`); pinning
    # `0.0.0.0:443` here would mask `qns_endpoint.zig:76` and break
    # the runner's `ipv6` testcase. The IPv6 wildcard accepts IPv4
    # via mapped addresses on Linux (the runner's deployment OS)
    # since `bindv6only` is `0` by default.
    set -- /qns-endpoint server -www /www -cert /certs/cert.pem -key /certs/priv.key
    if [ -n "${SSLKEYLOGFILE:-}" ]; then
      set -- "$@" -keylog-file "${SSLKEYLOGFILE}"
    fi
    if [ -n "${QLOGDIR:-}" ]; then
      set -- "$@" -qlog-dir "${QLOGDIR}"
    fi
    if [ -n "${retry_arg}" ]; then
      set -- "$@" "${retry_arg}"
    fi
    exec "$@"
    ;;
  client)
    if [ "${TESTCASE:-}" = "multiconnect" ]; then
      echo "quic-zig qns client does not support TESTCASE=${TESTCASE}" >&2
      exit 127
    fi
    server_arg="${SERVER:-}"
    if [ -z "${server_arg}" ] && [ -n "${REQUESTS:-}" ]; then
      first_request=${REQUESTS%% *}
      server_arg=${first_request#*://}
      server_arg=${server_arg%%/*}
    fi
    if [ -z "${server_arg}" ]; then
      server_arg="server4:443"
    fi
    server_name_arg="${SERVER_NAME:-}"
    if [ -z "${server_name_arg}" ]; then
      server_name_arg=${server_arg%%:*}
    fi
    set -- /qns-endpoint client -server "${server_arg}" -server-name "${server_name_arg}" -downloads /downloads -requests "${REQUESTS:-}" -testcase "${TESTCASE:-}"
    if [ -n "${SSLKEYLOGFILE:-}" ]; then
      set -- "$@" -keylog-file "${SSLKEYLOGFILE}"
    fi
    if [ -n "${QLOGDIR:-}" ]; then
      set -- "$@" -qlog-dir "${QLOGDIR}"
    fi
    exec "$@"
    ;;
  *)
    echo "unknown ROLE=${ROLE:-unset}" >&2
    exit 127
    ;;
esac
