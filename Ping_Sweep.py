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

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *

if len(sys.argv) != 2:
	print "Usage: ./ping_sweeper.py 192.168.56.0"
	sys.exit()	

ipaddrs = str(sys.argv[1])

iprange = ipaddrs.split('.')[0] + '.' + ipaddrs.split('.')[1] + '.' + ipaddrs.split('.')[2] + '.'

for addrs in range(100,254):
	res = sr1(IP(dst=iprange+str(addrs))/ICMP(),timeout=1, verbose=0)
	if res == None:
		pass
	else:
		print iprange+str(addrs) + ' is up'
