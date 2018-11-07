#!/usr/bin/env python2
#------------------------------------------------------------------
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Co-Author Lilith Wyatt (liwyatt)
#------------------------------------------------------------------
# Copyright (c) 2014-2017 by Cisco Systems, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the Cisco Systems, Inc. nor the
#    names of its contributors may be used to endorse or promote products
#    derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS "AS IS" AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#------------------------------------------------------------------


import signal
import socket
import sys

HOST = "127.0.0.1"
PORT = 2500
BUFFERSIZE = 1024
STATES = ("Listening", "Authenticated", "Quit")
STATE_COMMANDS = ("auth", "quit")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

def sigint_handler(signal, frame):
	# Quit on ctrl-c
	print "\nSIGINT received, stopping\n"
	s.close()
	sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

while 1:
	connection, address = s.accept()
	print "\nNew client from %s:%d" % (address[0], address[1])
	state = STATES[0]
	try:
		while  state != STATES[2]:
			data = connection.recv(BUFFERSIZE).rstrip()
			if not data:
				break
			print "Received: %s" % (data)
			
			if state == STATES[0]:
				if data == STATE_COMMANDS[0]:
					print "Transitioning from %s to %s" % (STATES[0], STATES[1])
					state = STATES[1]
					connection.send("OK\n")
					continue
			elif state == STATES[1]:
				if data == STATE_COMMANDS[1]:
					print "Transitioning from %s to %s" % (STATES[1], STATES[2])
					state = STATES[2]
					connection.send("OK\n")
					continue
			# Should have done something by now on a valid command
			print "Invalid command '%s' for state '%s'" % (data, state)
			connection.send("INVALID\n")
	except socket.error as e:
		print "Socket error %s, lost client" % (str(e))
				
	connection.close()
