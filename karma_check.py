#!/usr/bin/env python
#
# karma_check.py - d.e.switzer 
# ZGF2aWQgZG90IGUgZG90IHN3aXR6ZXIgYXQgdGVoZ21haWx6Cg==
# - test to send out random probes from various brand MAC addresses.
# 
#
# - Phones w/ url were found via Youtube
# - Phones w/ initials were found via personal contact.  Assume
#   cell purchased in, and used on a provider located in the United States.
#
#dev#Motorola Moto G#14:30:C6:B2:XX:XX# https://youtube/watch?v=6FbpDBbw1x4
#dev#Motorola Moto E#90:68:C3:30:XX:XX#- D.E.
#dev#Moto X (2014)#60:BE:B5:83:XX:XX#- D.E.
#dev#Samsung S5#F0:25:B7:C3:XX:XX# https://youtube/watch?v=ePZVq-UWjtE
#dev#Samsung S4#10:A5:D0:FA:XX:XX#- J.E. 
#dev#Samsung S6#E8:50:8B:40:XX:XX# https://youtube/watch?v=VVAbU6n-BdE
#dev#Samsung Galaxy Note2#38:AA:3c:FD:XX:XX #- K.S.
#dev#Apple iPhone 5c#68:AE:20:1F:XX:XX#- K.S.
#dev#Apple iPhone 5s#F0:CB:A1:D2:XX:XX# https://youtube/watch?v=eKdYhZgwwes
#dev#Apple iPhone 6#70:3E:AC:55:XX:XX#- A.O.
#dev#Apple iPhone 6 Plus#20:A2:E4:35:XX:XX# https://youtube/watch?v=ee8y5MiY4_8
#dev#Apple iPhone 6 Plus#FC:e9:98:BB:XX:XX#- K.S.
#dev#Nexus 5x#64:BC:0C:51:XX:XX#- C.M.
#dev#Nexus 6#F8:CF:C5:D2:XX:XX#- K.S.
#dev#Apple iPhone 6#F4:37:B7:D1:XX:XX#- J.P.

import argparse, random, string, logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

__author__ = 'd.e.switzer'

def get_me_some_args():
    parser = argparse.ArgumentParser(
        description='Script sends out randomized 802.11 probe requests.')
    parser.add_argument(
        '-i', '--interface', type=str, help='Wifi interface', required=True)
    parser.add_argument(
        '-m', '--moninterface', type=str, help='Wifi monitor interface', required=False, default='mon0')
    parser.add_argument(
        '-c', '--channel', type=str, help='Channel #', required=False, default='11')
    parser.add_argument(
        '-t', '--tag', type=str, help='Tag to search for in MAC address', required=False, default='62:82')
    args = parser.parse_args()
    interface = args.interface
    moninterface = args.moninterface
    channel = args.channel
    tag = args.tag
    return interface,moninterface,channel,tag

interface,moninterface,channel,tag = get_me_some_args()

SSID = ''
conf.iface = interface
int = interface
hw = interface
mac = ''
macs = ['14:30:C6','90:68:C3','60:BE:B5', 'F0:25:B7', '10:A5:D0', 'E8:50:8B', '38:AA:3C', '68:AE:20', 'F0:CB:A1', '70:3E:AC', '20:A2:E4', 'FC:E9:98', '64:BC:0C', 'F4:37:B7', '4e:4f:54', '53:4f:42', '52:49:47', '48:54:41', '4e:59:4d', '4f:52:45']

def randomssid(length):
        return ''.join(random.choice(string.lowercase) for i in range(length))

class Scapy80211():
    def  __init__(self,intf=int,ssid=SSID,source=mac,bssid='ff:ff:ff:ff:ff:ff'):
      self.rates = "\x03\x12\x96\x18\x24\x30\x48\x60"
      self.ssid    = ssid
      self.source  = source
      self.bssid   = bssid
      self.intf    = intf
      self.intfmon = 'mon0'
      conf.iface   = self.intfmon

      # create monitor interface using iw
      cmd = '/sbin/iw dev %s interface add %s type monitor >/dev/null 2>&1' \
        % (self.intf, self.intfmon)
      cmdintup = '/sbin/ifconfig %s up > /dev/null 2>&1' % (self.intfmon)
      try:
        os.system(cmd)
	os.system(cmdintup)
      except:
        raise

    def ProbeReq(self,count=1,ssid=SSID,dst='ff:ff:ff:ff:ff:ff'):
      if not ssid: ssid=self.ssid
      param =	Dot11ProbeReq()
      essid =	Dot11Elt(ID='SSID',info=ssid)
      rate1 =	"\x02\x04\x0b\x16"
      rate2 =	"\x82\x84\x0b\x16\x24\x30\x48\x6c"
      rate3 =	"\x03\x12\x96\x18\x24\x30\x48\x60"
      rate4 =	"\x82\x84\x8b\x96\x12\x24\x48\x6c"
      rates =	Dot11Elt(ID='Rates',info=rate4)
      dsset =	Dot11Elt(ID='DSset',info=chr(1))
      erpinfo = Dot11Elt(ID='ERPinfo',info='\x00')
      esrates =	Dot11Elt(ID='ESRates',info='\x0c\x18\x30\x60')
      tim =	Dot11Elt(ID='TIM',info='\x00\x01\x00\x00')

# Vendor specific extras.  Modeled after a Realtek device.  Add
# "/vendor" to the "pkt" definition below if you'd like to use them.
#
# These values are easy to find in WireShark under the "tagged options" for
# a wireless packet, and the variables below are named to be close or identical
# to how they are named in WireShark.
#
      uuidr = 		"\x10\x48\x00\x10\x52\x61\x6c\x69\x6e\x6b\x57\x50\x53\x2d\xac\x81\x12\xa1\xa3\x74"
      primarydevtype =	"\x10\x54\x00\x08\x00\x01\x00\x50\xf2\x04\x00\x01"
      rfbands = 	"\x10\x3c\x00\x01\x01"
      assocstate = 	"\x10\x02\x00\x02\x00\x00"
      configerror  =	"\x10\x09\x00\x02\x00\x00"
      devicepassid = 	"\x10\x12\x00\x02\x00\x00"
      devicename =   	"\x10\x11\x00\x0d\x52\x61\x6c\x69\x6e\x6b\x20\x43\x6c\x69\x65\x6e\x74"
      manufacturer = 	"\x10\x21\x00\x18\x52\x61\x6c\x69\x6e\x6b\x20\x54\x65\x63\x68\x6e\x6f\x6c\x6f\x67\x79\x2c\x20\x43\x6f\x72\x70\x2e"
      modelname = 	"\x10\x23\x00\x17\x52\x62\x6c\x6e\x6b\x20\x57\x69\x72\x65\x6c\x65\x73\x73\x20\x41\x64\x61\x70\x74\x65\x72\x10"
      modelnum = 	"\x10\x24\x00\x06\x52\x54\x32\x38\x30\x30"
      vendorextension = "\x10\x49\x00\x06\x00\x37\x2a\x00\x01\x20"
      hdcap = 		"\x2d\x1a\x6e\x01\x02\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
      hdcap2 =		"\x00\x00\x00\x00\x00\x00\x0e\x00\x00\x00\x00\x00"
      extendedcap = 	"\x7f\x01\x01"
      vendor = 		Dot11Elt(ID=221,len=167,info="\x00\x50\xf2\x04\x10\x4a" + 
           		"\x00\x01\x10\x10" + "\x3a\x00" + "\x01\x00\x10\x08" + "\x00\x02" + "\x22\x8c" + 
			uuidr + primarydevtype + rfbands + assocstate + configerror + devicepassid + devicename + 
			manufacturer + modelname + modelnum + vendorextension +hdcap + hdcap2 + extendedcap)

      pkt = RadioTap()\
        /Dot11(type=0,subtype=4,addr1=dst,addr2=self.source,addr3=self.bssid)\
        /param/essid/rates/esrates/tim

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
print " Note: the channel option only sets the 4th pair in the"
print "       MAC address, simply to show what channel that" 
print "       broadcast was on if hopping around channels."
print "       on if hopping around channels."
print "       The tag option just sets the 5th and 6th pair in the"
print "       MAC, so  you can search for that in a packet dump even"
print "       if the channel field is changed."
print "-------------------------------------------------"
print "Sending probe requests via " + hw + "..."
print "-------------------------------------------------"
for mac in macs:
	yay = ":"
	seq = (mac, channel, tag) 
	testmac = yay.join ( seq )
#	SSID = "i appear missing"
	SSID = randomssid(32)
	sdot11 = Scapy80211(intf=int,source=testmac,ssid=SSID)
	packet = sdot11.ProbeReq()
