#!/usr/bin/python
#
# option252_check.py - d.e.switzer # ZGF2aWQgZG90IGUgZG90IHN3aXR6ZXIgYXQgdGVoZ21haWx6Cg==
# - Script that sends DHCPINFORM packets to broadcast and shows
# responses.  Used for checking for MITM attempts.
#

import logging,socket,fcntl,struct
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Set up the interface
if len(sys.argv) > 1:
    hw = sys.argv[1]
    conf.iface = sys.argv[1]
else:
    hw = 'eth5'
    conf.iface = hw

conf.checkIPaddr = False

# \FC is just 252 in hex
option252="\xFC"

print "-------------------------------------------------"
print "WPAD: DHCP Option 252 spoof/poison attack checker - d.switzer 2015"
print "-------------------------------------------------"
print " "
print "Sending on " + hw

dhcp_inform = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src="172.16.78.42",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr="f0:76:1c:e0:08:25",ciaddr="172.16.78.42")/DHCP(options=[("message-type","inform")])/DHCP(options=[("param_req_list",option252), "end"])

ans,unans = srp(dhcp_inform,multi=True,timeout=1,verbose=0)

print "-------------------------------------------------"
for p in ans:
	print "Response from: " + p[1][Ether].src, p[1][IP].src
	print "-------------------------------------------------"
	print p[1][DHCP].options
