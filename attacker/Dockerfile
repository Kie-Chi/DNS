FROM python:3.9-slim
RUN pip install scapy
RUN apt-get update && \
    apt-get install -y libuv1-dev dnsutils tmux tcpdump && \
    rm -rf /var/lib/apt/lists/*
RUN apt-get update
RUN apt-get install -y build-essential || apt-get install -y build-essential --fix-missing
RUN apt-get install -y libpcap-dev || apt-get install -y libpcap-dev --fix-missing
RUN apt-get install -y cmake || apt-get install -y cmake --fix-missing
RUN apt-get install -y dnsperf || apt-get install -y dnsperf --fix-missing
WORKDIR /app