FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    python3.11 \
    python3-pip \
    python3.11-venv \
    python3.11-dev \
    curl \
    wget \
    git \
    build-essential \
    libz-dev \
    zlib1g-dev \
    libssl-dev \
    xz-utils \
    ca-certificates \
    mingw-w64 \
    gcc-mingw-w64-i686 \
    gcc-mingw-w64-x86-64 \
    ccache \
    gcc-multilib \
    g++-multilib \
    lib32z1-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp
COPY requirements.txt .
RUN python3.11 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r requirements.txt && \
    rm requirements.txt

ENV PATH="/opt/venv/bin:$PATH"

RUN mkdir -p /opt/nim && cd /opt/nim && \
    curl -L -o nim.tar.xz --retry 5 --retry-delay 3 --connect-timeout 30 --max-time 600 \
        https://nim-lang.org/download/nim-2.2.6-linux_x64.tar.xz && \
    tar -xf nim.tar.xz --strip-components=1 && \
    rm nim.tar.xz

ENV PATH="/opt/nim/bin:$PATH"

WORKDIR /Mythic/poopsie/agent_code
COPY poopsie/agent_code/poopsie.nimble .
RUN nimble install -y --depsOnly

RUN curl -L -o donut_shellcode-2.0.0.tar.gz https://github.com/MEhrn00/donut/releases/download/v2.0.0/donut_shellcode-2.0.0.tar.gz && \
    tar -xf donut_shellcode-2.0.0.tar.gz && \
    cd donut_shellcode-2.0.0 && \
    make && \
    cp donut / && \
    cd .. && \
    rm -rf donut_shellcode-2.0.0 donut_shellcode-2.0.0.tar.gz

RUN mkdir -p /opt/openssl-build && cd /opt/openssl-build && \
    wget -q https://www.openssl.org/source/openssl-3.5.4.tar.gz && \
    tar -xzf openssl-3.5.4.tar.gz && \
    cd openssl-3.5.4 && \
    ./Configure mingw64 \
        --cross-compile-prefix=x86_64-w64-mingw32- \
        --prefix=/opt/openssl-mingw64-static \
        no-shared \
        -static -static-libgcc && \
    make -j$(nproc) && \
    make install && \
    make clean && \
    ./Configure mingw \
        --cross-compile-prefix=i686-w64-mingw32- \
        --prefix=/opt/openssl-mingw32-static \
        no-shared \
        -static -static-libgcc && \
    make -j$(nproc) && \
    make install && \
    cd / && rm -rf /opt/openssl-build

RUN set -eux; \
    curl -L "https://github.com/upx/upx/releases/download/v5.0.2/upx-5.0.2-amd64_linux.tar.xz" \
      -o upx.tar.xz; \
    tar -xf upx.tar.xz; \
    dir="$(tar -tf upx.tar.xz | head -1 | cut -d/ -f1)"; \
    cp "$dir/upx" /upx; \
    chmod +x /upx; \
    rm -rf "$dir" upx.tar.xz

ENV PATH="/usr/lib/ccache:$PATH"
ENV CCACHE_DIR="/tmp/ccache"
ENV CCACHE_MAXSIZE="500M"

WORKDIR /Mythic
COPY main.py main.py
COPY poopsie poopsie

ENV PYTHONPATH=/Mythic/poopsie/agent_code

CMD ["python3.11", "main.py"]
