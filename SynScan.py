#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys

if len(sys.argv) !=3:
	print "Usage: python %s IP [Range Start]-[Range End]" % sys.argv[0]
	print "Usage: python %s 192.168.56.101 1-1000" % sys.argv[0]
	sys.exit()
	
myIP = sys.argv[1]
startPort = int(sys.argv[2].split('-')[0])
endPort = int(sys.argv[2].split('-')[1])

for myPort in range(startPort, endPort):
	res = sr1(IP(dst=myIP)/TCP(dport=myPort), timeout=1, verbose=0)
	if res == None:
		pass
	else:
		if int(res[TCP].flags) == 18:
			print 'This port is open ' + str(myPort)
		else:
			pass
