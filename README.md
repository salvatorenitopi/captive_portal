# Captive Portal

### Short Description

This script allows you to create a rogue access point that forces the user to interact with a phishing web-page. This can be used for conducting red team engagements or Wi-Fi security testing.

### Installation

captive_portal requires [python](https://www.python.org/) v2+ to run.
Install all the needed packages and the python dependencies using the setup.sh script.
```sh
$ chmod +x setup.sh
$ ./setup.sh
```
This script was tested on Kali Linux 2019 - 4.19.13-1kali1 (2019-01-03)

### Quickstart

Once the installation is complete you can run the interactive mode using the following command (which is an "interface" for the captive_portal.sh script):
```sh
python auto_captive_portal.py
```
Then you can follow the instructions on the screen:
```python
[*] Checking dependencies...

[*] iptables Installed
[*] psmisc Installed
[*] net-tools Installed
[*] aircrack-ng Installed
[*] screen Installed
[*] hostapd Installed
[*] isc-dhcp-server Installed
[*] python-dev Installed
[*] python-pip Installed
[*] python-dev Installed
[*] python-pip Installed

[*] Killing dangerous processes...
[*] Searching interfaces...


####################################
# Select AP interface              #
####################################
1)  wlan0  (device_name_here)
2)  wlan1  (device_name_here)
####################################
Choose: 1


####################################
# Select Monitor interface         #
####################################
1)  wlan1  (device_name_here)
99) No Monitor Interface
####################################
Choose: 1


[*] Scanning networks using wlan1...


##############################################
# MAC  Ch  Signal  SSID                      #
##############################################
1)  AA:BB:CC:DD:EE:FF  6  -49  network_1
2)  AA:CC:BB:DD:EE:FF  1  -63  network_2
3)  AA:DD:CC:BB:EE:FF  1  -73  network_3
##############################################
Choose Target: 1
Choose Addittionals Deauth Targets (Separated by space): 


[*] Putting wlan1 in monitor mode...
[*] wlan1 is now in monitor mode


####################################
# Module                           #
####################################
1)  _splash_page
2)  en_generic_router
3)  it_generic_router
####################################
Choose: 1


####################################
# Settings                         #
####################################
-) AP Channel (6): 
-) AP SSID (network_1): 
-) AP Password (None): 


# EXECUTION
```

### DNS Server
The DNS server script allows the attacker to response to all dns queries with a custom ip address. This is used just to emulate a real dns server, the script will always forward any tcp request to the default gateway (so you can provide any custom ip).

To run the script please execute the following command:
```sh
python dns_server.py -a <response_address>
```

### WEB Server
The WEB server is the core of the system, it allows the attacker to provide a phishing webpage to the victim. Any request to the root path (/) will be redirected to a secondary path (/index.html) with a 302 redirect code (this is needed to emulate the behavior of a real captive portal).

To run the script please execute the following command:
```sh
python web_server.py -a <bind_address> -p <bind_port> -m <chosen module> [-s <network_ssid>]
```
As you can see it is possible to specify any bind address and any bind port, then you can choose one of the available modules. Some modules gives you the ability to specify the SSID of the victim network, you can set this parameter using -s.

### Custom modules

To create a custom module, please put all the static files in a folder in the path modules/ and put the template in the path templates/. To make the new module available in the script, please edit the file templates/template_list.py as follow:
```python
template_list = {
  
  "_splash_page": { "template": "_splash_page.html", "module": "_splash_page" },

  "it_generic_router": { "template": "it_generic_router.html", "module": "generic" },
  "en_generic_router": { "template": "en_generic_router.html", "module": "generic" },

  "new_module_name": { "template": "new_template.html", "module": "module_static_files_folder" }
}
```
To create a new template you can start from the following example: templates/empty.html

### Custom run

If you want to customize the execution of the main script, you can type:
```sh
./captive_portal.sh [Options] [Mode]
```
This will allow you to set the following custom options:
```sh
OPTIONS:
  -i       interface
  -c       channel
  -s       ssid
  -m       module
  -p       password (not required)

MODES:
  list       list all modules available
  start      start the captive_portal
  stop       stop the captive_portal
  check      check users.txt and lease file
  script     generate a script

EXAMPLE: 
   ./captive_portal.sh -i wlan0 -c 1 -s TEST -m en_generic_router start
```

### What's the difference with the old version?

With the new version I tried to remove as much dependencies as possibile, so instad of using Apache as web-server and Bind as dns-server, I built a new python implementation. 

This will also allows you to create a modules starting from a templates (requiring less code and having more customization options).

### WARNING

To keep things simple i decided to use the default web-server provided by Flask, which has a known RCE vulnerability (more info and PoC here: [exploit-db](https://www.exploit-db.com/exploits/43905)). So be careful if you are using the script in a hostile environment, especially if debug is set to True (this refers to web_server.py).

```sh
nmap 127.0.0.1 -p 80 -sV
Starting Nmap 7.70 ( https://nmap.org ) at 2019-05-07 19:19 CEST
Nmap scan report for localhost (127.0.0.1)
Host is up (0.00021s latency).

PORT     STATE SERVICE VERSION
80/tcp open  http    Werkzeug httpd 0.14.1 (Python 2.7.15)

Nmap done: 1 IP address (1 host up) scanned in 6.48 seconds
```

### DISCLAIMER
Usage of captive_portal for attacking infrastructures without prior mutual consistency can be considered as an illegal activity. It is the final user's responsibility to obey all applicable local, state and federal laws. Authors assume no liability and are not responsible for any misuse or damage caused by this program.