'''
    Module used to fetch SOA (domain and IP) records for the given target domain
'''
import utils
from scapy.all import IP, UDP, DNS, DNSQR, sr1

# Py3: expandLayers is no longer needed as Scapy handles layers more directly.
# We can access answers via ans[DNS].an[DNSRR] for multiple answers.
# The original implementation was also flawed as it only got the first answer.

def getSoaForDomain(args):
    # Find NS records for the target domain
    pkt = IP(dst="8.8.8.8") / UDP(sport=utils.getRandomPort()) / DNS(rd=1, qd=DNSQR(qname=args.targetDomain, qtype="NS"))
    ans = sr1(pkt, verbose=False, timeout=5)
    
    if not ans or not ans.haslayer(DNS) or not ans[DNS].an:
        print("Could not resolve NS records for the domain.")
        return False

    # Py3: rdata for domain names is in bytes, so we decode it.
    # Collect all authoritative server domains from the answer section
    args.soaDomain = [rr.rdata.decode('utf-8').rstrip('.') for rr in ans[DNS].an if rr.type == 2] # 2 is NS type
    
    if not args.soaDomain:
        print("No NS records found in the response.")
        return False
        
    args.soaIP = []
    print(f"Found authoritative servers: {args.soaDomain}")
    
    for domain in args.soaDomain:
        # Find A record (IP) for each NS domain
        pkt = IP(dst="8.8.8.8") / UDP(sport=utils.getRandomPort()) / DNS(rd=1, qd=DNSQR(qname=domain, qtype="A"))
        ans = sr1(pkt, verbose=False, timeout=5)
        
        if ans and ans.haslayer(DNS) and ans[DNS].an:
            # Collect all IPs from the answer section
            for rr in ans[DNS].an:
                if rr.type == 1: # 1 is A type
                    args.soaIP.append(rr.rdata)
    
    if not args.soaIP:
        print("Could not resolve IP for any authoritative servers.")
        return False

    print(f"Resolved IPs: {args.soaIP}")
    return True