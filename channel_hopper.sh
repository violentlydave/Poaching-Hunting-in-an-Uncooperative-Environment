#!/bin/bash
#
# Simple script to change channels on interfaces while
# running wifi tests. - d.switzer 2015
#
# North America uses Channels 1 - 11 (2412 - 2462Mhz center channels w/ 22Mhz width)
# Japan uses Channels 1 - 14 (14 only for 802.11b - 2412 - 2484 Mhz centerchannels w/ 22mhz width)
# Majority of the rest of the world uses Channels 1 - 13 (2412 - 2472Mhz center channels w/ 22mhz width) 
#
# Change STARTCHANNEL and ENDCHANNEL as needed, defaults to North American channels.

IFACE="wlan18"
STARTCHANNEL=10
ENDCHANNEL=10

if [[ $# -eq 0 ]] ; then
	echo "-------------------------------------------------"
	echo "channel_hopper.sh - d.switzer 2015"
	echo " simple script to change channels on interfaces"
        echo "-------------------------------------------------"
	echo "" 
	echo " usage:"
	echo " ./channel_hopper.sh interfacename"
	echo "    .. interfacename being the wifi interface you'd like to change"
	echo
	exit 0
fi
IFACE=$1

        echo "-------------------------------------------------"
echo "channel_hopper.sh - d.switzer 2015"
echo "-------------------------------------------------"
echo "Let's go!  Looping from channel $STARTCHANNEL to $ENDCHANNEL ..."
echo "-------------------------------------------------"

for A in $(eval echo "{$STARTCHANNEL..$ENDCHANNEL}"); do
	ifconfig $IFACE down
	iwconfig $IFACE mode managed
	iwconfig $IFACE channel $A 
	iwconfig $IFACE mode monitor
	ifconfig $IFACE up
	ifconfig mon0 up

	./karma_check.py -i $IFACE --channel $A 
done

