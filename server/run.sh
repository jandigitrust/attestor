#!/bin/bash

cd -- "$(dirname -- "$0")" || exit 1

if cargo build --locked; then
    # Public Nginx and the collector must use the same certificate/key pair.
    default_certs=/tmp/confido
    if [[ -d /etc/confido ]]; then
        default_certs=/etc/confido
    fi
    args=("${1:-127.0.0.1:8001}" "${2:-${CONFIDO_CERTS_DIR:-$default_certs}}" "${3:-sha256}")
    if [[ -n "${4:-}" ]]; then
        args+=(--tls-hostname "$4")
    fi

    binary="$PWD/target/debug/attestor-server"
    echo "Collector certificate: ${args[1]}/certificate.pem"
    # A bad cached certificate must not take the existing collector offline.
    if ! sudo "$binary" "${args[@]}" --check-config; then
        echo "Invalid collector certificate configuration; existing server was not stopped" >&2
        exit 1
    fi
    if ! sudo python3 "$PWD/stop_existing.py" "${args[0]}"; then
        echo "Could not stop the existing server" >&2
        exit 1
    fi

    RUST_LOG="${RUST_LOG:-info}" sudo -E "$binary" "${args[@]}"
else
    echo "Build failed, not running the server"
    exit 1
fi
