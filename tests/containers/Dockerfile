ARG BASE_IMAGE=debian:stable-slim
FROM ${BASE_IMAGE}
ARG DISTRO=debian
ENV DEMUDHRA_CONTAINER_TEST=1
RUN set -eu; \
    case "$DISTRO" in \
      debian|ubuntu) \
        apt-get update; \
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
          ca-certificates openssl python3 dash busybox libnss3-tools default-jre-headless; \
        rm -rf /var/lib/apt/lists/* ;; \
      fedora) \
        dnf install -y ca-certificates openssl python3 dash busybox nss-tools java-21-openjdk-headless findutils; \
        dnf clean all ;; \
      alpine) \
        apk add --no-cache ca-certificates openssl python3 dash nss-tools openjdk21-jre-headless ;; \
      archlinux) \
        pacman -Syu --noconfirm ca-certificates ca-certificates-utils ca-certificates-mozilla \
          openssl python dash busybox nss jre-openjdk-headless; \
        pacman -Scc --noconfirm ;; \
      opensuse) \
        zypper --non-interactive refresh; \
        zypper --non-interactive install --no-recommends ca-certificates ca-certificates-mozilla \
          openssl python3 dash busybox mozilla-nss-tools java-21-openjdk-headless findutils; \
        zypper clean --all ;; \
      *) exit 1 ;; \
    esac; \
    printf '%s\n' "$DISTRO" > /.demudhra-disposable-container
WORKDIR /work
COPY . /work
ENTRYPOINT ["sh", "tests/containers/inside.sh"]
