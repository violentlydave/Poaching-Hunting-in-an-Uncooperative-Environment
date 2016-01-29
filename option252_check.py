#!/usr/bin/python
#
# option252_check.py -- sends DHCPINFORM packets to broadcast and shows
# responses.  Used for checking for MITM attempts.
#i@

import argparse,logging,socket,fcntl,struct
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

def get_me_some_args():
    parser = argparse.ArgumentParser(
        description='Script sends out DHCPINFORM option252 broadcast and analyzes responses.')
    parser.add_argument(
        '-i', '--interface', type=str, help='Network interface', required=True)
    args = parser.parse_args()
    interface = args.interface
    return interface

def get_ip_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

def get_mac_address(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

interface = get_me_some_args()
hw = interface
conf.iface = interface
my_ip = get_ip_address(interface)
my_mac = get_mac_address(interface)
conf.checkIPaddr = False
option252="\xFC"

print "-------------------------------------------------"
print "WPAD: DHCP Option 252 spoof/poison attack checker - d.switzer 2015"
print "-------------------------------------------------"
print " "
print "Sending on " + hw

ether 	= Ether(dst="ff:ff:ff:ff:ff:ff")
ip	= IP(src=my_ip,dst="255.255.255.255")
udp	= UDP(sport=68,dport=67)
# note, ciaddr = "desired ip" you're asking for. We default to current IP but can be different..
bootp	= BOOTP(chaddr=my_mac,ciaddr=my_ip)
dhcpmsg	= DHCP(options=[("message-type","inform")])
dhcpopt	= DHCP(options=[("param_req_list",option252), "end"])

dhcp_inform = ether/ip/udp/bootp/dhcpmsg/dhcpopt
ans,unans = srp(dhcp_inform,multi=True,timeout=1,verbose=0)

print "-------------------------------------------------"
for p in ans:
	print "Response from: " + p[1][Ether].src, p[1][IP].src
	print "-------------------------------------------------"
	print p[1][DHCP].options
