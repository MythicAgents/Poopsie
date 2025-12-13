FROM debian:bookworm-slim

# Install required packages including Nim dependencies
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
    ccache \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
WORKDIR /tmp
COPY requirements.txt .
RUN python3.11 -m venv /opt/venv && \
    /opt/venv/bin/pip install --upgrade pip && \
    /opt/venv/bin/pip install -r requirements.txt && \
    rm requirements.txt

# Set the virtual environment path
ENV PATH="/opt/venv/bin:$PATH"

# Install Nim compiler and nimble
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y && \
    echo 'export PATH=/root/.nimble/bin:$PATH' >> /root/.bashrc

ENV PATH="/root/.nimble/bin:$PATH"

# Copy project files
WORKDIR /Mythic
COPY main.py main.py
COPY poopsie poopsie

# Pre-install all Nim dependencies (makes builds much faster)
WORKDIR /Mythic/poopsie/agent_code
RUN /root/.nimble/bin/nimble install -y --depsOnly

# Install donut for shellcode generation
RUN curl -L -o donut_shellcode-2.0.0.tar.gz https://github.com/MEhrn00/donut/releases/download/v2.0.0/donut_shellcode-2.0.0.tar.gz && \
    tar -xf donut_shellcode-2.0.0.tar.gz && \
    cd donut_shellcode-2.0.0 && \
    make && \
    cp donut / && \
    cd .. && \
    rm -rf donut_shellcode-2.0.0 donut_shellcode-2.0.0.tar.gz

# Enable ccache for faster recompilation
ENV PATH="/usr/lib/ccache:$PATH"
ENV CCACHE_DIR="/tmp/ccache"
ENV CCACHE_MAXSIZE="500M"

# Final setup
WORKDIR /Mythic

ENV PYTHONPATH=$PYTHONPATH:/Mythic/poopsie/agent_code

CMD ["python3.11", "main.py"]
