'''
    Module used to validate the input
'''
# validate fields
from validators import ipv4, domain
# used to get the current public IP
import json
from urllib.request import urlopen
# colors
from vars import ccolors

# validate the input based on the passed args
def validateInput(args):
    if not args.victim or not args.targetDomain or not args.addressToForge:
        print(ccolors.FAIL + "Missing one or more required positional arguments: victimIP, targetDomain, yourDNSIP" + ccolors.NC)
        return False
        
    if not ipv4(args.victim):
        print(ccolors.WARNING + 'Victim is not a valid IP address\n' + ccolors.FAIL + 'Terminating...'  + ccolors.NC)
        return False

    if not domain(args.targetDomain): #supports IDN
        print(ccolors.WARNING + 'Target is not a valid domain\n' + ccolors.FAIL + 'Terminating...'  + ccolors.NC)
        return False

    if args.addressToForge.lower() == 'myip':
        try:
            # get user's current IP address from this URL
            # Py3: urlopen returns bytes, must be decoded before loading with json
            response = urlopen('http://jsonip.com').read()
            args.addressToForge = json.loads(response.decode('utf-8'))['ip']
            print(ccolors.OKGREEN + f"Resolved 'myip' to your public IP: {args.addressToForge}" + ccolors.NC)
        except Exception as e:
            print(ccolors.FAIL + f"Could not resolve your public IP. Error: {e}" + ccolors.NC)
            return False
    elif not ipv4(args.addressToForge):
        print(ccolors.WARNING + 'Spoofing IP is not a valid IP address\n' + ccolors.FAIL + 'Terminating...' + ccolors.NC)
        return False

    if args.demo and not ipv4(args.demo):
        print(ccolors.WARNING + 'Demo IP is not a valid IP address\n' + ccolors.FAIL + 'Terminating...' + ccolors.NC)
        return False

    return True