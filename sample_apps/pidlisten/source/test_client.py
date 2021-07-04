#!/usr/bin/python

import socket
import sys

ip = "127.0.0.1"
port = 9090

#msg format : <pid>.<# of test cases>
#although it doesn't really do much right now
msg = "1234.4321"

try:
    cli = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    cli.connect((ip,port))   
except:
    print("Could not connect to %s, %d, exiting!" % (ip,port))
    sys.exit(0)

cli.send(msg)
print(cli.recv(4096))

