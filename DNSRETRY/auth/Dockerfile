FROM python:3.9-slim
RUN pip install scapy
RUN apt-get update && \
    apt-get install -y tmux tcpdump && \
    rm -rf /var/lib/apt/lists/*
RUN pip install dnslib
WORKDIR /app
EXPOSE 53
CMD ["python3", "server.py"]