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
    exec /qns-endpoint server -listen 0.0.0.0:443 -www /www -cert /certs/cert.pem -key /certs/priv.key ${retry_arg}
    ;;
  client)
    echo "nullq qns client endpoint is not implemented yet" >&2
    exit 127
    ;;
  *)
    echo "unknown ROLE=${ROLE:-unset}" >&2
    exit 127
    ;;
esac
