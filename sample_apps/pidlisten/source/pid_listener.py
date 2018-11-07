#!/usr/bin/env python2
#---------------------
# Vulnerable binary, doesn't really do much 
# Faulty pidlistener server for testing purposes
# Integer overflow -> malloc crash 
# (Integer of 8192 causes crash)
#
# September 2015, created within ASIG
# Author Lilith Wyatt (liwyatt)
#
# Copyright (c) 2015 by Cisco Systems, Inc.
# All rights reserved.
#------------------------------------------------------------------

import socket
import os
from ctypes import *
from ctypes.util import find_library
from sys import exit,argv
import threading
from time import localtime

#-----------
# ctype structs for holding testcase/session data

class fuzz_tc(Structure):
    _fields_ = [("status",c_int),
                ("tc_id",c_int)]

class fuzz_session(Structure):
    _packed_ = ("tc",)
    _fields_ = [("ip",c_char_p),
                ("port",c_int),
                ("pid",c_int),
                ("tc_len",c_short),
                ("tc",c_void_p)] 
#-------------------------------
# Options for sessions 
TIMEOUT = 2
MAX_SESSIONS = 5

try:
    libc_loc = find_library("c")
    LIBC = CDLL(libc_loc)
except:
    print "Unable to find Libc, exiting!"
    exit(-1)


#-------------------------------
# Vulnerable server initialization
def server_init():

    
    bindip = "127.0.0.1"
    socket_family = socket.AF_INET

    try:
        if argv[1] == "-6":
            socket_family = socket.AF_INET6
            bindip = "::1" 
        elif argv[1] == '-u':
            socket_family = socket.AF_UNIX
            bindip = "fdsa" 
    except IndexError:
        pass

    bindport = 8888 
    pid = c_uint()

    try:
        serv = socket.socket(socket_family,socket.SOCK_STREAM) 
        serv.bind((bindip,bindport))
        serv.listen(MAX_SESSIONS)
    except TypeError:
        try:
            serv.bind(bindip)
            serv.listen(MAX_SESSIONS)
        except Exception as e:
            print e
            print "Unable to bind to %s,%d!!" % (bindip,bindport)
            exit(-1)

    #Spawn thread for each fuzz session (if mulitple)
    while True:
        try:
            cli_sock,cli_addr = serv.accept() 
            fuzz_session = threading.Thread(target=client_handler,args=(cli_sock,cli_addr))
        except Exception as e: #UDS error
            print e
            cli_sock = serv.accept() 
            fuzz_session = threading.Thread(target=client_handler,args=(cli_sock))
            
    
        fuzz_session.start()


# Code for handling a given fuzzing session
# - Propagates fuzz_session struct with connection info
# - Allocates enough memory to handle all the testcases
# - Records the information into a file upon timeout/crash/normal exit
#---------------------

def client_handler(cli_sock,cli_addr=None): 
    try:
        ip = cli_addr[0]
        port = cli_addr[1] 
        cli_sock.settimeout(TIMEOUT)
        fs = fuzz_session(ip,port,-1,-1,None)
    except:
        ip = "fdsa"
        cli_sock.settimeout(TIMEOUT)
        fs = fuzz_session(ip,-1,-1,-1,None)

#generate log file name
    timestamp = localtime()
    fname = "%d_%d_%d_%d_%d_%s" % (timestamp.tm_year,
                                    timestamp.tm_mon,
                                    timestamp.tm_mday,
                                    timestamp.tm_hour,
                                    timestamp.tm_min,
                                    ip)


#listen for initialization message:
# 4 byte - pid
# . separator
# 4 byte - number of test cases 
    msg = cli_sock.recv(4096).split('.')

    if len(msg) != 2 or len(msg[0]) > 4 or len(msg[1].rstrip()) > 4:
        print "Invalid session init: %s" % (msg,)
        exit(-1)    

    try:
        dirty_input_int = int(msg[0])
        dirty_input_short = int(msg[1])
        if dirty_input_int >= c_uint(-1).value or dirty_input_short >= c_ushort(-1).value:
            print "Invalid init values given: %d, %d" % (dirty_input_int, dirty_input_short)
            exit(-1)
    except:
        print "Unsavory input given: %s, %s" % (msg[0],msg[1]) 
     
    #populate data to struct
    try:
        fs.pid = c_int(dirty_input_int)
        fs.tc_len = c_short(dirty_input_short)
    except:
        print "Unable to parse msg: %s" % (msg,)

    #allocate enough space to hold fuzz_tc structs 
#! vulnerable line
    allocate_space = c_ushort(sizeof(fuzz_tc) * fs.tc_len)
    LIBC.malloc.restype = c_void_p 
    ret = LIBC.malloc(allocate_space)

    print "Buffer (size: %d) allocated at 0x%x" % (allocate_space.value, ret)

    if ret == 0:
        print "Unable to allocate memory! Exiting!"
        exit(-1)

    fs.tc = cast(ret,c_void_p)
    print "fs.tc = 0x%x" % (fs.tc)

    tmp = c_void_p(None)
    tmp_struct = None

    #write arbitrary value (for now) to each struct
    for i in range(0,fs.tc_len):
        tmp = c_void_p(fs.tc + (i*sizeof(fuzz_tc)))
        tmp_struct = fuzz_tc.from_address(tmp.value)
        tmp_struct.status = i
        print "status: %d" % (i,)
    
    cli_sock.send("[^.^] Launching %d testcases for pid %d" % (fs.tc_len,fs.tc_len)) 
    
if __name__ == '__main__':
    
    try:
        os.remove("fdsa")
    except:
        pass
    server_init()
