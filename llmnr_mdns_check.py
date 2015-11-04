#!/usr/bin/python

import logging,socket,fcntl,struct
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

conf.checkIPaddr = False

# fo sho?  def.
def randomstuff(length):
        return ''.join(random.choice(string.lowercase) for i in range(length))

def get_ip_addy(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 0x8915, struct.pack('256s', ifname[:15]))[20:24])

def get_mac_addy(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
    return ':'.join(['%02x' % ord(char) for char in info[18:24]])

# Options .. like an interface on commandline.
if len(sys.argv) > 1:
    hw = sys.argv[1]
    conf.iface = sys.argv[1]
else:
    hw = 'eth5'
    conf.iface = hw

my_ip = get_ip_addy(hw)
my_mac = get_mac_addy(hw)
my_query = 'wpad'
my_qtype = 'A'
queryid = random.getrandbits(16)
# standard broadcast for LLMNR and mDNS
llmnr_target_ip = '224.0.0.252'
llmnr_target_mac = '01:00:5E:00:00:FC'
mdns_target_ip = '224.0.0.251'
mdns_target_mac = '01:00:5E:00:00:FB'

print "-------------------------------------------------"
print "LLMNR/mDNS spoof/poison attack checker - d.switzer 2015"
print "-------------------------------------------------"
print "Sending on " + hw
print ""
print
print "-------------------------------------------------"
print "Sending LLMNR request for " + my_query + " .."
ethernet = Ether(src=my_mac,dst=llmnr_target_mac)
ip = IP(src=my_ip,dst=llmnr_target_ip)
udp = UDP(sport=5355,dport=5355)
llmnr = LLMNRQuery()
llmnr.id = queryid
llmnr.qr = 0
llmnr.opcode = 0
llmnr.qdcount = 1
llmnr.qd = DNSQR(qname=my_query,qtype=my_qtype)
pkt = ethernet/ip/udp/llmnr
ans,unans=srp(pkt,multi=True,verbose=0,timeout=1)
for p in ans:
        print "-------------------------------------------------"
        print "Response from: " + p[1][Ether].src, p[1][IP].src
        print "-------------------------------------------------"
print ans
print unans

my_query = randomstuff(16)
print "-------------------------------------------------"
print "Sending LLMNR request for random host (" + my_query + ") .."
ethernet = Ether(src=my_mac,dst=llmnr_target_mac)
ip = IP(src=my_ip,dst=llmnr_target_ip)
udp = UDP(sport=5355,dport=5355)
llmnr = LLMNRQuery()
llmnr.id = queryid
llmnr.qr = 0
llmnr.opcode = 0
llmnr.qdcount = 1
llmnr.qd = DNSQR(qname=my_query,qtype=my_qtype)
pkt = ethernet/ip/udp/llmnr
ans,unans=srp(pkt,multi=True,verbose=0,timeout=1)
for p in ans:
        print "-------------------------------------------------"
        print "Response from: " + p[1][Ether].src, p[1][IP].src
        print "-------------------------------------------------"
print ans
print unans
print ""


###################################################################

#reset a thing or so..
my_query = "wpad"

print "-------------------------------------------------"
print "Sending mDNS request for " + my_query + ".."
ethernet = Ether(src=my_mac,dst=mdns_target_mac)
ip = IP(src=my_ip,dst=mdns_target_ip)
udp = UDP(sport=5353,dport=5353)
dns = DNS()
dns.id = queryid
dns.qr = 0 
dns.opcode = 0
dns.qdcount = 1
dns.rq = 0
dns.qd = DNSQR(qname=my_query,qtype='A')
pkt=ethernet/ip/udp/dns
ans,unans=srp(pkt,multi=True,verbose=0,timeout=1)
for p in ans:
        print "-------------------------------------------------"
        print "Response from: " + p[1][Ether].src, p[1][IP].src
        print "-------------------------------------------------"
print ans
print unans

my_query = randomstuff(16)
print "-------------------------------------------------"
print "Sending mDNS request for random host (" + my_query + ") .."
ethernet = Ether(src=my_mac,dst=mdns_target_mac)
ip = IP(src=my_ip,dst=mdns_target_ip)
udp = UDP(sport=5353,dport=5353)
dns = DNS()
dns.id = queryid
dns.qr = 0
dns.opcode = 0
dns.qdcount = 1
dns.rq = 0
dns.qd = DNSQR(qname=my_query,qtype='A')
pkt=ethernet/ip/udp/dns
ans,unans=srp(pkt,multi=True,verbose=0,timeout=1)
for p in ans:
        print "-------------------------------------------------"
        print "Response from: " + p[1][Ether].src, p[1][IP].src
        print "-------------------------------------------------"
print ans
print unans


