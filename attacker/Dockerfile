FROM python:3.9-slim
RUN pip install scapy
RUN apt-get update && \
    apt-get install -y iproute2 dnsutils tmux tcpdump && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app