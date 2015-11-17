#!/usr/bin/python
#
# karma_check.py - d.e.switzer # ZGF2aWQgZG90IGUgZG90IHN3aXR6ZXIgYXQgdGVoZ21haWx6Cg==
# - script to send out NetBios-NS broadcasts and check for responses.
#

import argparse,logging,socket,fcntl,struct
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

__author__ = 'd.switzer'

def get_me_some_args():
    parser = argparse.ArgumentParser(
        description='Script sends out randomized NetBIOS-NS checks and analyzes any responses.')
    # Add arguments
    parser.add_argument(
        '-i', '--interface', type=str, help='Network interface', required=True)
    args = parser.parse_args()
    interface = args.interface
    return interface

interface = get_me_some_args()
hw = interface
conf.iface = interface
conf.checkIPaddr = False

# fo sho?  def.
def randomstuff(length):
        return ''.join(random.choice(string.lowercase) for i in range(length))

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

print "-------------------------------------------------"
print "NBNS spoof/poison attack checker - d.switzer 2015"
print "-------------------------------------------------"
print "Sending on " + hw

#let's build some packets.. ok, one packet.
nsquery = "WPAD"
myip 	= get_ip_address(hw)
ether 	= Ether(dst='ff:ff:ff:ff:ff:ff')
ip 	= IP(src=myip, dst='255.255.255.255')
udp 	= UDP(sport=137, dport=137)
nbns 	= NBNSQueryRequest(SUFFIX="file server service",QUESTION_NAME=nsquery, QUESTION_TYPE='NB')
nbnsquery = ether/ip/udp/nbns

print "-------------------------------------------------"
print "Checking for WPAD via NBNS broadcast.."
print "-------------------------------------------------"
ans,unans = srp(nbnsquery,multi=True,timeout=1,verbose=0)

for p in ans:
	print p[1][Ether].src, p[1][IP].src
	print "-------------------------------------------------"
print ans

# now a random "question" name.
nsquery = randomstuff(16)
print "-------------------------------------------------"
print "Checking for random (" + nsquery + ") hostname via NBNS broadcast.."
print "-------------------------------------------------"
nbns = NBNSQueryRequest(SUFFIX="file server service",QUESTION_NAME=nsquery, QUESTION_TYPE='NB')
nbnsquery = ether / ip / udp / nbns
ans,unans = srp(nbnsquery,multi=True,timeout=1,verbose=0)
for p in ans:
        print p[1][Ether].src, p[1][IP].src
        print "-------------------------------------------------"
print ans
