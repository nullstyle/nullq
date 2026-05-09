#!/bin/sh
set -eu

/setup.sh

case "${TESTCASE:-}" in
  ""|handshake|transfer|longrtt|chacha20|multiplexing|retry|resumption|zerortt|keyupdate|blackhole|handshakeloss|transferloss|handshakecorruption|transfercorruption|multiconnect|connectionmigration|amplificationlimit|ipv6|rebind-addr|rebind-port|crosstraffic|versionnegotiation|goodput|throughput|v2)
    # Most testcase names are runner-side hints (the runner injects
    # the named network simulator profile and validates outcomes
    # from the qlog / pcap); the qns endpoint's behaviour is
    # generic. Four exceptions are routed by the wrapper:
    #   - retry            → adds the server `-retry` flag below.
    #   - connectionmigration → server-side: adds `-pref-addr [::]:444`
    #                       so the server binds an alt-port socket and
    #                       advertises a `preferred_address` transport
    #                       parameter (RFC 9000 §18.2). Client-side:
    #                       handled inside the binary via the
    #                       `server46` hostname heuristic at
    #                       `qns_endpoint.zig:921` — same TESTCASE
    #                       value, the wrapper hands the runner's
    #                       ROLE choice back to the binary.
    #   - keyupdate        → currently client-side only via
    #                       `ClientConnectionOptions.request_key_update`;
    #                       server-side latch is a known gap.
    ;;
  preferredaddress|http3)
    # preferredaddress: deliberately not wired — the runner's
    #   `connectionmigration` testcase already exercises the
    #   server-side `preferred_address` advertise via the `CM` cell
    #   above. `preferredaddress` as a standalone testcase name is
    #   not part of the official interop runner's matrix today.
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
    # `connectionmigration` (server-side) needs the server to
    # advertise a `preferred_address` transport parameter
    # (RFC 9000 §18.2) and to be reachable on the alt-port. We
    # bind `[::]:444` and let the binary fill in the runner's
    # statically-allocated v4/v6 IPs (see
    # `interop_runner_server_ipv4` / `_ipv6` in `qns_endpoint.zig`).
    pref_addr_arg=""
    if [ "${TESTCASE:-}" = "connectionmigration" ]; then
      pref_addr_arg="[::]:444"
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
    if [ -n "${pref_addr_arg}" ]; then
      set -- "$@" -pref-addr "${pref_addr_arg}"
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
