#!/bin/sh
set -eu
[ "${DEMUDHRA_CONTAINER_TEST-}" = 1 ] && [ -f /.demudhra-disposable-container ] || {
    printf '%s\n' 'Refusing to run outside the disposable demudhra test image.' >&2
    exit 1
}
timeout 45 python3 tools/generate.py --check --verify-pems
timeout 45 python3 tests/test_files.py --shell dash
timeout 45 python3 tests/test_stores.py
timeout 45 python3 tests/test_macos.py
timeout 45 python3 tests/test_entrypoint.py
if command -v busybox >/dev/null 2>&1; then
    timeout 45 python3 tests/test_files.py --shell 'busybox sh'
fi
timeout 45 python3 tests/containers/native.py
