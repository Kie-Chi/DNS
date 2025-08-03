FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools \
    tcpdump \
    vim \
    iproute2 \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

EXPOSE 53/udp

RUN pip install --no-cache-dir -r requirements.txt