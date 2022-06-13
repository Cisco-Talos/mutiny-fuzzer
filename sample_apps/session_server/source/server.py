#!/usr/bin/env python

import random
import signal
import socket
import sys

HOST = "0.0.0.0"
PORT = 2500
BUFFERSIZE = 1024
STATES = ("Listening", "Authenticated", "Quit")
STATE_COMMANDS = ("auth", "quit", "do_stuff")

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))
s.listen(1)

def sigint_handler(signal, frame):
	# Quit on ctrl-c
	print("\nSIGINT received, stopping\n")
	s.close()
	sys.exit(0)
signal.signal(signal.SIGINT, sigint_handler)

while 1:
	connection, address = s.accept()
	print("\nNew client from %s:%d" % (address[0], address[1]))
	state = STATES[0]
	try:
		token = None
		
		while  state != STATES[2]:
			data = connection.recv(BUFFERSIZE).rstrip()
			if not data:
				break
			print("Received: %s" % (data))
			
			if state == STATES[0]:
				if data == STATE_COMMANDS[0]:
					print("Transitioning from %s to %s" % (STATES[0], STATES[1]))
					state = STATES[1]
					token = str(random.randint(1, 100))
					connection.send("%s\n" % (token))
					continue
			elif state == STATES[1]:
				if data[-len(token):] == token:
					if data[0:len(STATE_COMMANDS[1])] == STATE_COMMANDS[1]:
						print("Transitioning from %s to %s" % (STATES[1], STATES[2]))
						state = STATES[2]
						connection.send("OK\n")
						continue
					elif data[0:len(STATE_COMMANDS[2])] == STATE_COMMANDS[2]:
						connection.send("OK\n")
						continue
			# Should have done something by now on a valid command
			print("Invalid command '%s' for state '%s'" % (data, state))
			connection.send("INVALID\n")
	except socket.error as e:
		print("Socket error %s, lost client" % (str(e)))
				
	connection.close()
