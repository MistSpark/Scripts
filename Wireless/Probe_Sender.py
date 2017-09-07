#!/usr/bin/env python

'''
   *                  (
 (  `               ) )\ )                      ) 
 )\))(   (       ( /((()/(           )  (    ( /( 
((_)()\  )\  (   )\())/(_))`  )   ( /(  )(   )\())
(_()((_)((_) )\ (_))/(_))  /(/(   )(_))(()\ ((_)\ 
|  \/  | (_)((_)| |_ / __|((_)_\ ((_)_  ((_)| |(_)
| |\/| | | |(_-<|  _|\__ \| '_ \)/ _` || '_|| / / 
|_|  |_| |_|/__/ \__||___/| .__/ \__,_||_|  |_\_\ 
                          |_|
'''

from scapy.all import *
import os

interface = "wlan2"
m = "FF:FF:FF:FF:FF:FF"
rm = RandMAC()

def channel_hopper():
	global channel
	channel = random.randrange(1,15)
	os.system("iwconfig %s channel %d" % (interface, channel))

def ProbeSender():
	num = 0
	frame = RadioTap()/Dot11(addr1=m, addr2=rm, addr3=rm)/\
	Dot11ProbeReq()/Dot11Elt(ID="SSID",info="")
	while True:
		try:
			channel_hopper()
			print "[+] Channel Number: " + str(channel)
			num += 1
			print "[+] Sending Probe Request: %s" % num
			sendp(frame, iface=interface, inter=.5)
		except KeyboardInterrupt:
			break

ProbeSender()
