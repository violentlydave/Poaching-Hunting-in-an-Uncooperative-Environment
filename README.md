# Poaching: Hunting without Permission#

 This is the code that goes along with the paper "Poaching: Hunting without
 Permission".

 Thanks to Joff Thyer for his sample Scapy code.  Heavily used in the
 EvilAP tests.

------------------------------------------------------------------

- option252_check.py
This python script uses the Scapy library to send “DHCPINFORM” broadcast messages to see if a WPAD response is returned.  This would be a response with a URL in the option 252 area of the DHCP response.

- nbns_check.py
This Python script uses the Scapy library to send NetBIOS Name Service broadcast messages to attempt to resolve the host “wpad”, then another message trying to resolve a random hostname.

- llmnr_mdns_check.py
This Python script uses the Scapy library to send LLMNR and mDNS broadcast messages, first to try to resolve the host “wpad”, then another message trying to resolve a random hostname.

- eviltwin_check.py
This Python script uses the Scapy library to send out 802.11 Probe Request packets from multiple MAC addresses set up to look like a variety of cell phones looking for a known wifi network.  It loops through the list of MAC addresses and each one requests a unique random 16bit long SSID.   Each MAC address is set so the last 4 bits are uniform to allow for the tester to watch for the packets and any responses via “Tshark” or “TCPdump”.

