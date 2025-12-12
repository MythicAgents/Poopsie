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
# Dependencies will be installed automatically from poopsie.nimble when building
RUN curl https://nim-lang.org/choosenim/init.sh -sSf | sh -s -- -y && \
    echo 'export PATH=/root/.nimble/bin:$PATH' >> /root/.bashrc

ENV PATH="/root/.nimble/bin:$PATH"

# Copy project files
WORKDIR /Mythic
COPY main.py main.py
COPY poopsie poopsie

# Final setup
WORKDIR /Mythic

ENV PYTHONPATH=$PYTHONPATH:/Mythic/poopsie/agent_code

CMD ["python3.11", "main.py"]
