'''
    Utilities modules
'''

from random import randint, choice
from string import ascii_lowercase, digits
from scapy.all import Ether, ARP, srp1

def getRandomPort():
    # In a real scenario, source port selection by OS is more complex
    # but for simulation, this is fine.
    return randint(1024, 65535)

def getRandomSubdomain():
    return ''.join(choice(ascii_lowercase + digits) for _ in range(10)) + '.'

def getRandomTXID():
    return randint(0, 65535)

def getRandomIPv4():
    return '.'.join(str(randint(0, 255)) for _ in range(4))

def getMAC(ip):
    # Craft an ARP request packet
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=ARP.who_has, pdst=ip)
    # Send and receive a single response
    ans = srp1(pkt, verbose=False, timeout=5)
    if ans:
        return ans[ARP].hwsrc
    else:
        return None