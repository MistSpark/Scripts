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

interface='wlan2'
dpkt = 1

def detecter(fm):
	if fm.haslayer(Dot11):
		if (fm.haslayer(Dot11Deauth)):
			global dpkt
			print "Deauth Detected: ", dpkt
			dpkt = dpkt + 1

sniff(iface=interface, prn=detecter)

