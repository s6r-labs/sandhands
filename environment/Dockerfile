FROM docker.io/library/debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

ARG DEBIAN_FRONTEND=noninteractive
ARG DEBIAN_SNAPSHOT=20260803T000000Z

RUN sed -i \
        -e "s|URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}|" \
        -e "s|URIs: http://deb.debian.org/debian-security$|URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}|" \
        /etc/apt/sources.list.d/debian.sources \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99snapshot \
    && apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        conntrack \
        coreutils \
        curl \
        dnsutils \
        iproute2 \
        iptables \
        iputils-ping \
        jq \
        less \
        lsof \
        netcat-openbsd \
        nftables \
        procps \
        python3 \
        python3-jsonschema \
        socat \
        strace \
        sudo \
        tcpdump \
        util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 2001 range-subject \
    && useradd --no-create-home --no-user-group --uid 2001 --gid 2001 --shell /usr/sbin/nologin range-subject \
    && groupadd --gid 2002 range-target \
    && useradd --no-create-home --no-user-group --uid 2002 --gid 2002 --shell /usr/sbin/nologin range-target \
    && groupadd --gid 2003 range-fixture \
    && useradd --no-create-home --no-user-group --uid 2003 --gid 2003 --shell /usr/sbin/nologin range-fixture \
    && useradd --create-home --shell /bin/bash candidate \
    && printf 'candidate ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/candidate \
    && chmod 0440 /etc/sudoers.d/candidate

WORKDIR /workspace
ENV PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
USER candidate

CMD ["bash"]
