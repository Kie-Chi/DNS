FROM python:3.9-slim
RUN pip install scapy
RUN apt-get update && \
    apt-get install -y tmux tcpdump dnsutils && \
    rm -rf /var/lib/apt/lists/*
RUN pip install dnslib
RUN apt-get update
RUN apt-get install -y build-essential libpcap-dev
WORKDIR /app
EXPOSE 53
