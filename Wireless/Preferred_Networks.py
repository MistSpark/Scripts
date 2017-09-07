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


#Where Have you been..

from scapy.all import *

interface = 'wlan2'
probeReqs = []
def sniffProbe(p):
	if p.haslayer(Dot11ProbeReq):
		netName = p.getlayer(Dot11ProbeReq).info
		if netName not in probeReqs:
			probeReqs.append(netName)
			print '[+] The MAC Address Of The Device: ' + p.addr2.upper()
			print '[+] Detected New Probe Request   : ' + netName
			print '------------------------------------------------------'
sniff(iface=interface, prn=sniffProbe)
