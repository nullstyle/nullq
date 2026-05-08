#!/bin/sh
set -eu

/setup.sh

case "${TESTCASE:-}" in
  ""|handshake|transfer|longrtt|chacha20|multiplexing|retry|resumption|zerortt|keyupdate|blackhole|handshakeloss|transferloss|handshakecorruption|transfercorruption|multiconnect)
    ;;
  *)
    echo "quic-zig qns endpoint does not support TESTCASE=${TESTCASE:-unset}" >&2
    exit 127
    ;;
esac

case "${ROLE:-server}" in
  server)
    retry_arg=""
    if [ "${TESTCASE:-}" = "retry" ]; then
      retry_arg="-retry"
    fi
    set -- /qns-endpoint server -listen 0.0.0.0:443 -www /www -cert /certs/cert.pem -key /certs/priv.key
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
