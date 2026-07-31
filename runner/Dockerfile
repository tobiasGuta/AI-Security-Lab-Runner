FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    bash \
    ca-certificates \
    curl \
    wget \
    jq \
    yq \
    ripgrep \
    grep \
    sed \
    gawk \
    coreutils \
    findutils \
    file \
    less \
    zip \
    unzip \
    python3 \
    python3-pip \
    nodejs \
    npm \
    golang-go \
    openssl \
    xxd \
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    nmap \
    socat \
    httpie \
    git \
    make \
    gcc \
    g++ \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# Invariant 18: The runner uses a non-root user (agent: 10001).
RUN groupadd -g 10001 agent && \
    useradd -u 10001 -g agent -m -s /bin/bash agent

RUN mkdir -p /workspace /scratch /tmp && \
    chown -R agent:agent /workspace /scratch /tmp

USER agent
WORKDIR /workspace

CMD ["sleep", "infinity"]
