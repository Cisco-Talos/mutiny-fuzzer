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
# This file is the frame for the monitor functionality. 
# By default this will only allow signalling from the child
# monitor process to the main process. Also allows for 
# differentiation between CTRL+C and the target process
# dying.  
#------------------------------------------------------------------
import time
import socket
import subprocess

# Copy this file to your project's mutiny classes directory to
# implement a long-running thread to monitor your target
# This is useful for watching files, logs, remote connections,
# PIDs, etc in parallel while mutiny is operating
# This parallel thread can signal Mutiny when it detects a crash

# A monitor can also die/respawn based on the process.
# A monitor should pass the information necessary for the next one when it dies.   

class Monitor(object):

    def __init__(self):
        self.crashEvent = None
        self.harness_port = -1
        self.targetIP = ""
        self.targetPort = 0

    # This function will run asynchronously in a different thread to monitor the host
    def monitorTarget(self, targetIP, targetPort, lock_condition):
        self.targetIP = targetIP
        self.targetPort = targetPort     
        self.lock_condition = lock_condition

        self.retIP = targetIP
        self.retPort = targetPort        
    
    def die(self):
        return (self.retIP,self.retPort)

    # just keep execution locked up here until unlockCondition is met
    def lockExecution(self):
        ret_val = ""
        # uncomment if you want monitoring, change testing_bin to whatever.
        while not len(ret_val):
            #ret_val = self.lockCondition("always_unlocked")
            ret_val = self.lockCondition(self.lock_condition,self.targetIP,self.targetPort)
            time.sleep(1) 

        return ret_val


    # a given lockCondition should return a value on unlock and "" or None on still locked.
    def lockCondition(self,condition,*args): 
        #print("Condition: %s, args: %s"%(condition,args))
        lock_dict = {
                    "remote_tcp_open": self.remote_tcp_open,
                    "local_process_listen":self.local_process_listen,
                    "always_unlocked":self.always_unlocked,
                    "ping_test": self.ping_test,
                    }

        return lock_dict[condition](args) 

    # OS: Any            
    # This conditional will unlock when it finds the requested port to be open for the 
    # specified IP address. Can be remote or local. Careful, as some servers (e.g. fork())
    # will not totally crash on a thread crash, and the port will remain open.
    # Arguments: <IP_ADDR> <PORT> <opt_timeout>
    def remote_tcp_open(self,args):
        IP = args[0]
        PORT = int(args[1])
        timeout = 2

        try:
            timeout = float(args[2])
        except:
            pass

        if ":" in IP:
            testsock = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        else:
            testsock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        testsock.settimeout(timeout)
        testsock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        try:
            testsock.connect((IP,PORT))
            testsock.close() 
            return "%s|%d"%(IP,PORT)   
        except Exception as e:
            if "Connection" not in str(e):
                print(str(e))
            return ""
                
            
    # OS: Linux
    # This conditional will unlock when it discovers the named service (e.g. 'testing_bin')
    # listening on a local port. It will return the IP and port as such: '127.0.0.1|8307' 
    # Arguments: <process_name>
    def local_process_listen(self,args):
        process_name = args[0] 
        # should also include windows sample... 
        port_test = subprocess.Popen(["/bin/netstat","-antp"],stdout=subprocess.PIPE)
        grep_filter= subprocess.Popen(["/bin/grep","-e",process_name],stdin=port_test.stdout,stdout=subprocess.PIPE)
        port_list = grep_filter.communicate()[0] 
        if port_list: 
            print(port_list)
        # no hits, keep locked
        if not len(port_list):
            return ""
        
        try:
            # process string to get IP:PORT
            # 'tcp  0  0 127.0.0.1:8307  0.0.0.0:*   LISTEN      1111/testing_bin'
            tmp = port_list.split("\n")[0]
            tmp = filter(None,tmp.split(" "))[3] # this should be 'IP:PORT' 
            port = tmp.split(":")[1]
            if int(port) > 0 and int(port) < 65536:
                tmp = tmp.replace(":","|")
                return tmp     # e.g. 127.0.0.1|8307
        except Exception as e:
            print(str(e)) 
            return ""

        return ""

    # Just here for a placeholder if you don't want a lock condition
    def always_unlocked(self,*args):
        return "127.0.0.1|0"
            

    # in case you need ping.
    def ping_test(self,args): 
        IP = args[0]
        PORT = 0
        timeout = .2
        msg = "\x80\x00\x00\x00\x00\x00\x00\x00"

        if ":" in IP:
            fam = socket.AF_INET6
            proto = socket.IPPROTO_ICMPV6 
        else:
            fam = socket.AF_INET
            proto = socket.IPPROTO_ICMP 
         
        ping_sock = socket.socket(fam,socket.SOCK_RAW,proto)
        #ping_sock.setsockopt(socket.SOL_IP,socket.IP_HDRINCL,1)
        ping_sock.settimeout(timeout)
        ping_sock.sendto(msg,(IP,0,0,0))
        ret_msg,ret_addr = ping_sock.recvfrom(4096)  
        ping_sock.close()
         
        if len(ret_msg):
            return "%s|%d"%(IP,self.targetPort)   
        else:   
            return ""
          


    # Used in tandem with an assorted harness on the target.
    # tcp socket but edit as needed
    def harness_signal(self,address,port,command):
        signal_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        signal_sock.connect((address,port))
        signal_sock.send(command)

    # targetIP = address to connect to
    # targetPort = port being connected to
    # Called when the fuzzer connects for the first time
    def start_harness_trace(self):
        self.harness_signal(self.targetIP,self.harness_port,"start")

    def stop_harness_trace(self):
        self.harness_signal(self.targetIP,self.harness_port,"stop")
