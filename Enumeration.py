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

import os
import sys
import errno

try:
	if len(sys.argv) < 3:
		print('[+] This is just a demo of the script')
		print('[+] Usage: %s IP Path_To_Save_The_Results') % sys.argv[0]
		print('[+] Example: %s 192.168.56.101 /root/Desktop/') % sys.argv[0]
		exit(0)
	else:
		pass
except Exception, e:
	print e

# IP Given by The USER...
ip = sys.argv[1]
# Path Entered by The USER...
path = sys.argv[2]

# Making a Folder to Save the Results...
if len(sys.argv) == 3 and not os.path.exists(path):
    os.makedirs(path)


res = "Enum"
grep = 'grep.txt'
os.system("nmap -sV -O -sC %s -oA %s/%s" %(ip,path,res))

os.system("cat  %s/%s.xml | grep 'portid' | cut -d ' ' -f 3 | cut -d '\"' -f 2 | grep '[0-9]' > %s/%s" %(path,res,path,grep))

with open('%s/grep.txt'%path, 'rU') as f:
  for line in f:
  	if '21' in line and len(line) == 3:
  		os.system('nmap -p %s --script=*ftp* %s -oN %s/FTP.txt' %(line[:-1],ip,path))
	if '22' in line and len(line) == 3:
  		os.system('nmap -p %s --script=*ssh* %s -oN %s/SSH.txt' %(line[:-1],ip,path))
  	if '23' in line and len(line) == 3:
  		os.system('nmap -p %s --script=*telnet* %s -oN %s/TELNET.txt' %(line[:-1],ip,path))
  	if '25' in line and len(line) == 3:
  		os.system('nmap -p %s --script=*smtp* %s -oN %s/SMTP.txt' %(line[:-1],ip,path))
  	if '53' in line and len(line) == 3:
  		os.system('nmap -p %s --script=*dns* %s -oN %s/DNS.txt' %(line[:-1],ip,path))
  		os.system('dnsrecon -t zonewalk -d %s -> %s/DNS_ZONEWALK.txt' %(ip,path))
  	if '80' in line and len(line) == 3:
  		os.system('nmap -p %s --script=*http* %s -oN %s/HTTP_80.txt' %(line[:-1],ip,path))
  		os.system('nikto -h http://%s -o %s/HTTP_NIKTO_80.txt' %(ip,path))
  	if '110' in line and len(line) == 4:
  		os.system('nmap -p %s --script=*pop3* %s -oN %s/POP3.txt' %(line[:-1],ip,path))
  	if '111' or '135' in line and len(line) == 4:
  		os.system('nmap -p %s --script=*rpc* %s -oN %s/RPC.txt' %(line[:-1],ip,path))
  	if '139' in line and len(line) == 4:
  		os.system('nbtscan -v %s > %s/NETBIOS.txt' %(ip,path))
  	if '445' in line and len(line) == 4:
  		os.system('nmap -p %s --script=*smb* %s -oN %s/SMB.txt' %(line[:-1],ip,path))
  		os.system('enum4linux -a %s > %s/SMB_ENUM4LINUX.txt' %(ip,path))
  	if '3389' in line and len(line) == 5:
  		os.system('nmap -p %s --script=*rdp* %s -oN %s/RDP.txt' %(line[:-1],ip,path))
