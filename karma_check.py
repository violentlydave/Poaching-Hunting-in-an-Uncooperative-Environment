#!/usr/bin/env python
#
# karma_check.py - d.e.switzer # ZGF2aWQgZG90IGUgZG90IHN3aXR6ZXIgYXQgdGVoZ21haWx6Cg==
# - test to send out random(ish) probes from various brand MAC addresses.
# 
# detect responses: tshark -i mon0 -Y "wlan.fc.type_subtype==5" | grep -i e0:28^C
#
#dev#Motorola Moto G#14:30:C6:B2:XX:XX# https://www.youtube.com/watch?v=6FbpDBbw1x4
#dev#Motorola Moto E#90:68:C3:30:XX:XX#- D.E.
#dev#Moto X (2014)#60:BE:B5:83:XX:XX#- D.E.
#dev#Samsung S5#F0:25:B7:C3:XX:XX# https://www.youtube.com/watch?v=ePZVq-UWjtE
#dev#Samsung S4#10:A5:D0:FA:XX:XX#- J.E. 
#dev#Samsung S6#E8:50:8B:40:XX:XX# https://www.youtube.com/watch?v=VVAbU6n-BdE
#dev#Samsung Galaxy Note2#38:AA:3c:FD:XX:XX #- K.S.
#dev#Apple iPhone 5c#68:AE:20:1F:XX:XX#- K.S.
#dev#Apple iPhone 5s#F0:CB:A1:D2:XX:XX# https://www.youtube.com/watch?v=eKdYhZgwwes
#dev#Apple iPhone 6#70:3E:AC:55:XX:XX#- A.O.
#dev#Apple iPhone 6 Plus#20:A2:E4:35:XX:XX# https://www.youtube.com/watch?v=ee8y5MiY4_8
#dev#Apple iPhone 6 Plus#FC:e9:98:BB:XX:XX#- K.S.
#dev#Nexus 5x#64:BC:0C:51:XX:XX#- C.M.
#dev#Nexus 6#F8:CF:C5:D2:XX:XX#- K.S.
#dev#Apple iPhone 6#F4:37:B7:D1:XX:XX#- J.P.
#

import random, string, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

# Set up the interface
if len(sys.argv) > 1:
    hw = sys.argv[1]
    conf.iface = sys.argv[1]
else:
    hw = 'wlan15'
    conf.iface = hw

SSID = ''
int = hw
mac = ''
# - macend = string to add onto fake macs so we cna track via tcpdump or tshark
macend = '62:82'
macs = ['14:30:C6:B2','90:68:C3:30','60:BE:B5:83', 'F0:25:B7:C3', '10:A5:D0:FA', 'E8:50:8B:40', '38:AA:3C:FD', '68:AE:20:1F', 'F0:CB:A1:D2', '70:3E:AC:55', '20:A2:E4:35', 'FC:E9:98:BB', '64:BC:0C:51', 'F4:37:B7:D1','42:55:52:4E:45:44','4E:4F:54:53:4F:42','52:49:47:48:54:41','4E:59:4D:4F:52:45']

def randomssid(length):
        return ''.join(random.choice(string.lowercase) for i in range(length))

class Scapy80211():
    def  __init__(self,intf=int,ssid=SSID,source=mac,bssid='00:11:22:33:66:60'):
      self.rates = "\x03\x12\x96\x18\x24\x30\x48\x60"
      self.ssid    = ssid
      self.source  = source
      self.bssid   = bssid
      self.intf    = intf
      self.intfmon = 'mon0'
      conf.iface = self.intfmon

      # create monitor interface using iw
      cmd = '/sbin/iw dev %s interface add %s type monitor >/dev/null 2>&1' \
        % (self.intf, self.intfmon)
      try:
        os.system(cmd)
      except:
        raise

    def ProbeReq(self,count=1,ssid=SSID,dst='ff:ff:ff:ff:ff:ff'):
      if not ssid: ssid=self.ssid
      param = Dot11ProbeReq()
      essid = Dot11Elt(ID='SSID',info=ssid)
      rates = Dot11Elt(ID='Rates',info=self.rates)
      dsset = Dot11Elt(ID='DSset',info='\x01')
      pkt = RadioTap()\
        /Dot11(type=0,subtype=4,addr1=dst,addr2=self.source,addr3=self.bssid)\
        /param/essid/rates/dsset

      print "-------------------------------------------------"
      print 'ProbeReq: SSID=[%s]|src=[%s]|count=%d' % (ssid,self.source,count)
      try:
        sendp(pkt,count=count,inter=0.1,verbose=0)
      except:
        raise

print "-------------------------------------------------"
print "Karma checker - 802.11 probe sender - d.switzer2015"
print "  * Based on code by Joff Thyer 2014"
print "  * Any credit is his, any blame is mine." 
print "-------------------------------------------------"
print " Please note: Script expects to use mon0 once interface"
print " is brought up, and interface is given as command line option:"
print "   ./karma_check.py wlan20"


print "Sending probe requests..."
for mac in macs:
	yay = ":"
	seq = (mac, macend) 
	testmac = yay.join ( seq )
	SSID = randomssid(32)
	sdot11 = Scapy80211(intf=int,source=testmac,ssid=SSID)
	packet = sdot11.ProbeReq()
	#srp(packet,verbose=1,multi=True)
