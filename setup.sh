#!/bin/bash

########################################################################################################################

echo; echo "[*] Updating system"
apt update; #apt upgrade -y

########################################################################################################################

echo; echo "[*] Installing software"
apt install iptables psmisc net-tools aircrack-ng screen hostapd isc-dhcp-server python-dev python-pip -y

echo "[*] Setting up software"
pip install requests pysocks responses flask pyOpenSSL --user

########################################################################################################################