#!/bin/sh
set -eu

/setup.sh

case "${TESTCASE:-}" in
  ""|handshake|transfer|longrtt|chacha20|multiplexing|retry|resumption|zerortt|keyupdate|blackhole|handshakeloss|transferloss|handshakecorruption|transfercorruption)
    ;;
  *)
    echo "nullq qns endpoint does not support TESTCASE=${TESTCASE:-unset}" >&2
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
    set -- /qns-endpoint client -server "${SERVER:-server:443}" -server-name "${SERVER_NAME:-server}" -downloads /downloads -requests "${REQUESTS:-}" -testcase "${TESTCASE:-}"
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
