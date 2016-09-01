#!/usr/bin/env python

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import sys
import time
from colorama import Fore,Back,Style

if len(sys.argv) !=3:
	print "Usage: python %s IP [Range Start]-[Range End]" % sys.argv[0]
	print "Usage: python %s 192.168.56.101 1-1000" % sys.argv[0]
	sys.exit()

myIP = sys.argv[1]
startPort = int(sys.argv[2].split('-')[0])
endPort = int(sys.argv[2].split('-')[1])

for myPort in range(startPort, endPort):
	res = sr1(IP(dst=myIP)/UDP(dport=myPort), timeout=3, verbose=0)
	time.sleep(0.5)
	if res == None:
		print Fore.GREEN + "This port is Open: " + str(myPort) + Fore.RESET
	elif (res.haslayer(ICMP)):
		if (int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) == 3):
			print "This port is Closed: " + str(myPort)
		elif (int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [1,2,9,10,13]):
			print "This port is Filtered: " + str(myPort)
		
