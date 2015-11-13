#!/usr/bin/python
#
# option252_check.py - d.e.switzer # ZGF2aWQgZG90IGUgZG90IHN3aXR6ZXIgYXQgdGVoZ21haWx6Cg==
# - Script that sends DHCPINFORM packets to broadcast and shows
# responses.  Used for checking for MITM attempts.
#

import logging,socket,fcntl,struct
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

__author__ = 'd.switzer'


# Set up the interface
if len(sys.argv) > 1:
    hw = sys.argv[1]
    conf.iface = sys.argv[1]
else:
    hw = 'eth5'
    conf.iface = hw

conf.checkIPaddr = False

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])
def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

# \FC is just 252 in hex
option252="\xFC"

print "-------------------------------------------------"
print "WPAD: DHCP Option 252 spoof/poison attack checker - d.switzer 2015"
print "-------------------------------------------------"
print " "
print "Sending on " + hw

my_ip = get_ip_address(hw)
my_mac = get_mac_address(hw)
dhcp_inform = Ether(dst="ff:ff:ff:ff:ff:ff")/IP(src=my_ip,dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=my_mac,ciaddr=my_ip)/DHCP(options=[("message-type","inform")])/DHCP(options=[("param_req_list",option252), "end"])

ans,unans = srp(dhcp_inform,multi=True,timeout=1,verbose=0)

print "-------------------------------------------------"
for p in ans:
	
	print "Response from: " + p[1][Ether].src, p[1][IP].src
	print "-------------------------------------------------"
	print p[1][DHCP].options
	print "-------------------------------------------------"

