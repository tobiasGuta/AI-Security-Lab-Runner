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

# Compile and install trusted runner helper binaries from module
COPY . /tmp/runner-build
RUN cd /tmp/runner-build && go build -o /usr/local/bin/sandbox-fs ./sandbox-fs && go build -o /usr/local/bin/sandbox-http ./sandbox-http && rm -rf /tmp/runner-build

# Non-root user setup (agent: 10001)
RUN groupadd -g 10001 agent && \
    useradd -u 10001 -g agent -m -s /bin/bash agent

RUN mkdir -p /scratch /tmp && \
    chown -R agent:agent /scratch /tmp

USER agent
WORKDIR /scratch

CMD ["sleep", "infinity"]
