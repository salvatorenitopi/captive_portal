# Original from http://code.activestate.com/recipes/491264/ (r4)
# Forked from https://gist.github.com/andreif/6040183

import socket
import os
import sys

############################################################

import argparse
parser = argparse.ArgumentParser(add_help=True, description='')

requiredArgs = parser.add_argument_group('required arguments')

requiredArgs.add_argument('-a', required=True, type=str, help="ADDRESS:\tServer query response (ex. 192.168.1.1)")

args = parser.parse_args()

if (args.a == None):
	print "[!] Argument -a ADDRESS can not be None"
	sys.exit(-1)

############################################################

try:
	pid = str(os.getpid())
	f = open('/tmp/dns_server.PID', 'w')
	f.write(pid)
	f.close()
except:
	pass

##########################################################

VAR_IP = str(args.a)

########################################################################################################################

class DNSQuery:
	def __init__(self, data):
		self.data=data
		self.dominio=''

		tipo = (ord(data[2]) >> 3) & 15		# Opcode bits
		if tipo == 0:						# Standard query
			ini=12
			lon=ord(data[ini])
			while lon != 0:
				self.dominio+=data[ini+1:ini+lon+1]+'.'
				ini+=lon+1
				lon=ord(data[ini])

	def respuesta(self, ip):
		packet=''
		if self.dominio:
			packet+=self.data[:2] + "\x81\x80"
			packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
			packet+=self.data[12:]                                         # Original Domain Name Question
			packet+='\xc0\x0c'                                             # Pointer to domain name
			packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
			packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
		return packet

########################################################################################################################

print 'pyminifakeDNS:: dom.query. 60 IN A %s' % VAR_IP

udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udps.bind(('',53))

try:

	while 1:
		data, addr = udps.recvfrom(1024)
		p=DNSQuery(data)
		udps.sendto(p.respuesta(VAR_IP), addr)
		print 'Answers: %s -> %s' % (p.dominio, VAR_IP)

except Exception, e:
	print 'Exception: ' + str(e)

except KeyboardInterrupt:
	print 'Quitting...'
	udps.close()

########################################################################################################################