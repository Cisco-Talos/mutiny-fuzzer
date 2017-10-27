#!/usr/bin/python
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
import subprocess
from time import sleep
import socket
import sys

fuzzer_ip = "127.0.0.1"
fuzzer_port = 6969

def main(log):
    connected = False  
    while not connected:
        try:
            fuzzer_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            fuzzer_sock.connect((fuzzer_ip,fuzzer_port))
            connected = True
        except:
            msg = "[x.x] No comms with fuzz harness, sleeping. (%s:%d)"%(fuzzer_ip,fuzzer_port)
            print msg
            fuzzer_sock = None
            sleep(1)
            sys.stdout.write("\b"*(len(msg)+1))
            sys.stdout.flush()

    try:
        while True:
            cmd = ["gdb","-x","harness_cmds.txt","--args"] 
            cmd = cmd + sys.argv[1:]
            print cmd
            proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) 
            resp,err = proc.communicate()
            print resp
              
            if "SIGSEGV" in resp:
                print "[^_^] got sometin!"
                if fuzzer_sock:
                    fuzzer_sock.send(resp)
                log.write(resp)
                log.write("\n****************\n"*5)

    except KeyboardInterrupt:
        import traceback
        print traceback.print_exc()
        return
    except Exception as e:
        print e


with open('log.txt','a') as log:

    if len(sys.argv) < 2:
        print "[x.x] Usage: %s <target_proc_name>"%sys.argv[0]
        sys.exit()

    main(log) 

