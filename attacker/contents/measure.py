#!/usr/bin/env python3

import os
import sys
import time
import uuid
import socket
from scapy.all import send, DNS, DNSQR, IP, UDP

# --- Configuration ---
FORWARDER_IP = "10.0.0.2"
AUTH_SERVER_IP = "10.0.0.3" # 你的权威服务器IP
ATTACKER_DOMAIN = "example.com"
CHAIN_LENGTH = 55
CHAIN_PREFIX = 'c'
CNAME_CHAIN_EXPECTED_END = f"{CHAIN_PREFIX}{CHAIN_LENGTH}.{ATTACKER_DOMAIN}."
TIMEOUT = 5

# RTT measurement settings
LOCAL_CACHE_RTT_THRESHOLD = 0.02 
CACHE_CHECK_ATTEMPTS = 5

# --- Color Codes ---
GREEN = '\033[92m'
RED = '\033[91m'
BLUE = '\033[94m'
YELLOW = '\033[93m'
ENDC = '\033[0m'
PAD_WIDTH = 55 # 对齐宽度


def get_ip_from_dns_payload(data):
    """从原始DNS响应数据中解析并提取第一个A记录的IP"""
    try:
        dns_resp = DNS(data)
        if dns_resp.an:
            for rr in dns_resp.an:
                if rr.type == 1: return rr.rdata
    except Exception: return None
    return None

def colorize_info(raw_str):
    """仅将字符串中的 '[INFO]' 标签着色"""
    return raw_str.replace("[INFO]", f"{BLUE}[INFO]{ENDC}")

def measure_forwarder():
    """
    精简输出，明确每一步检查的成功与失败。
    """
    # 1. Probe forwarder to get potentially stale IP
    test_uuid = uuid.uuid4().hex[:8]
    initial_qname = f"{test_uuid}.{ATTACKER_DOMAIN}"
    raw_info_str = f"[INFO] Probing forwarder for stale IP".ljust(PAD_WIDTH)
    sock1 = None
    ip_from_forwarder_chain = None
    try:
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock1.settimeout(TIMEOUT)
        sock1.bind(('0.0.0.0', 12345))
        req1_pkt = IP(dst=FORWARDER_IP)/UDP(sport=12345)/DNS(rd=1, qd=DNSQR(qname=initial_qname))
        send(req1_pkt, verbose=0)
        data1, addr1 = sock1.recvfrom(4096)
        print(f"{colorize_info(raw_info_str)} {GREEN}[SUCCESS]{ENDC}")
        ip_from_forwarder_chain = get_ip_from_dns_payload(data1)
    except Exception as e:
        print(f"{colorize_info(raw_info_str)} {RED}[FAIL]{ENDC} (Error: {e})")
        return False
    finally:
        if sock1: sock1.close()

    raw_info_str = f"[INFO] Validating probe response".ljust(PAD_WIDTH)
    if not ip_from_forwarder_chain:
        print(f"{colorize_info(raw_info_str)} {RED}[FAIL]{ENDC} (No A-record received)")
        return False
    print(f"{colorize_info(raw_info_str)} {GREEN}[PASS]{ENDC} (Got IP: {ip_from_forwarder_chain})")

    # 2. Query authoritative server for the ground truth IP
    raw_info_str = f"[INFO] Querying auth server for fresh IP".ljust(PAD_WIDTH)
    sock2 = None
    ip_from_direct_auth_query = None
    try:
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock2.settimeout(TIMEOUT)
        sock2.bind(('0.0.0.0', 12346))
        req2_pkt = IP(dst=AUTH_SERVER_IP)/UDP(sport=12346)/DNS(rd=1, qd=DNSQR(qname=CNAME_CHAIN_EXPECTED_END))
        send(req2_pkt, verbose=0)
        data2, addr2 = sock2.recvfrom(4096)
        print(f"{colorize_info(raw_info_str)} {GREEN}[SUCCESS]{ENDC}")
        ip_from_direct_auth_query = get_ip_from_dns_payload(data2)
    except Exception as e:
        print(f"{colorize_info(raw_info_str)} {RED}[FAIL]{ENDC} (Error: {e})")
        return False
    finally:
        if sock2: sock2.close()

    raw_info_str = f"[INFO] Validating auth response".ljust(PAD_WIDTH)
    if not ip_from_direct_auth_query:
        print(f"{colorize_info(raw_info_str)} {RED}[FAIL]{ENDC} (No A-record received)")
        return False
    print(f"{colorize_info(raw_info_str)} {GREEN}[PASS]{ENDC} (Got IP: {ip_from_direct_auth_query})")

    # 3. Pre-check: Ensure the two IPs are different for the test to be valid
    raw_info_str = f"[INFO] Verifying difference".ljust(PAD_WIDTH)
    if ip_from_forwarder_chain == ip_from_direct_auth_query:
        print(f"{colorize_info(raw_info_str)} {RED}[FAIL]{ENDC} (Stale and fresh IPs are identical)")
        print(f"{YELLOW}       Please check your authoritative server's logic.{ENDC}")
        return False
    print(f"{colorize_info(raw_info_str)} {GREEN}[PASS]{ENDC}")

    time.sleep(1) # Wait for cache to settle

    # 4. Verify cache on forwarder
    raw_info_str = f"[INFO] Running cache verification probes ({CACHE_CHECK_ATTEMPTS}x)".ljust(PAD_WIDTH)
    rtt_list = []
    ip_from_cache_check = None
    sock3 = None
    try:
        sock3 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock3.settimeout(TIMEOUT)
        sock3.bind(('0.0.0.0', 12347))
        req3_pkt = IP(dst=FORWARDER_IP)/UDP(sport=12347)/DNS(rd=1, qd=DNSQR(qname=CNAME_CHAIN_EXPECTED_END))
        for i in range(CACHE_CHECK_ATTEMPTS):
            send(req3_pkt, verbose=0)
            start_time = time.time()
            data3, addr3 = sock3.recvfrom(4096)
            end_time = time.time()
            rtt_list.append(end_time - start_time)
            if i == 0:
                ip_from_cache_check = get_ip_from_dns_payload(data3)
            time.sleep(0.05)
        print(f"{colorize_info(raw_info_str)} {GREEN}[SUCCESS]{ENDC}")
    except Exception as e:
        print(f"{colorize_info(raw_info_str)} {RED}[FAIL]{ENDC} (Error: {e})")
        return False
    finally:
        if sock3: sock3.close()

    # 5. Final Analysis Checks
    raw_info_str = f"[INFO] Validating cache probe response".ljust(PAD_WIDTH)
    if not ip_from_cache_check:
        print(f"{colorize_info(raw_info_str)} {RED}[FAIL]{ENDC} (No A-record received)")
        return False
    print(f"{colorize_info(raw_info_str)} {GREEN}[PASS]{ENDC} (Got IP: {ip_from_cache_check})")

    # Check 1: Caching Behavior
    raw_info_str = "[INFO] Check: Caching behavior (IP)".ljust(PAD_WIDTH)
    behavior_vulnerable = (ip_from_cache_check != ip_from_direct_auth_query)
    if behavior_vulnerable:
        print(f"{colorize_info(raw_info_str)} {GREEN}[PASS]{ENDC} (Returned stale IP {ip_from_cache_check})")
    else:
        print(f"{colorize_info(raw_info_str)} {RED}[FAIL]{ENDC} (Returned fresh IP {ip_from_cache_check})")
        return False

    # Check 2: Cache Location
    min_rtt = min(rtt_list)
    raw_info_str = "[INFO] Check: Cache location (RTT)".ljust(PAD_WIDTH)
    print(f"{colorize_info(raw_info_str)}")
    print(f"{YELLOW}       (RTTs measured: {[f'{r:.4f}s' for r in rtt_list]}){ENDC}")
    if min_rtt < LOCAL_CACHE_RTT_THRESHOLD:
        print(f"       {''.ljust(PAD_WIDTH)} {GREEN}[PASS]{ENDC} (Min RTT {min_rtt:.4f}s is low)")
        return True # Both checks passed
    else:
        print(f"       {''.ljust(PAD_WIDTH)} {RED}[FAIL]{ENDC} (Min RTT {min_rtt:.4f}s is high)")
        return False

if __name__ == '__main__':
    if os.geteuid() != 0:
        print(f"{YELLOW}[!] WARNING: Running without root. Scapy may not work correctly.{ENDC}")
    
    print(f"[*] Starting measurement for DNS forwarder: {FORWARDER_IP}...")
    
    is_vulnerable = measure_forwarder()
    
    print("\n" + "-" * 60)
    print("[*] Final Conclusion:")
    if is_vulnerable:
        print(f"    {RED}[VULNERABLE]{ENDC}")
    else:
        print(f"    {GREEN}[NOT VULNERABLE]{ENDC}")
    print("-" * 60)