#!/bin/sh
set -eu
usage() {
    cat <<'HELP'
Usage: sh tests/containers/run.sh [--engine docker|podman] [DISTRO ...]
Build disposable test images and run them without host filesystem mounts.
DISTRO is debian, ubuntu, fedora, alpine, archlinux, or opensuse.
Without DISTRO arguments all six run. No image is pushed or released.
HELP
}
engine=
case ${1-} in
    -h|--help) usage; exit 0 ;;
    --engine)
        [ "$#" -ge 2 ] || { usage >&2; exit 1; }
        engine=$2
        shift 2
        case $engine in docker|podman) ;; *) usage >&2; exit 1 ;; esac
        ;;
esac
if [ -z "$engine" ]; then
    if command -v docker >/dev/null 2>&1; then
        engine=docker
    elif command -v podman >/dev/null 2>&1; then
        engine=podman
    else
        printf '%s\n' 'NOT RUN: docker and podman are unavailable.' >&2
        exit 2
    fi
fi
command -v "$engine" >/dev/null 2>&1 || {
    printf '%s\n' "NOT RUN: $engine is unavailable." >&2
    exit 2
}
[ "$#" -gt 0 ] || set -- debian ubuntu fedora alpine archlinux opensuse
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)
for distro do
    case $distro in
        debian) image=debian:stable-slim ;;
        ubuntu) image=ubuntu:24.04 ;;
        fedora) image=fedora:latest ;;
        alpine) image=alpine:latest ;;
        archlinux) image=archlinux:latest ;;
        opensuse) image=opensuse/tumbleweed:latest ;;
        *) printf '%s\n' "Unknown distro: $distro" >&2; exit 1 ;;
    esac
    tag=demudhra-test-$distro
    timeout 45 "$engine" build --pull --build-arg "BASE_IMAGE=$image" --build-arg "DISTRO=$distro" \
        -f "$repo/tests/containers/Dockerfile" -t "$tag" "$repo"
    timeout 45 "$engine" run --rm --network none "$tag"
done
