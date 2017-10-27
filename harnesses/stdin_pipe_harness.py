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
import socket
import sys

fuzzer_ip = "192.168.2.2"
fuzzer_port = 6969
cmdline_pass = False

def main(log):
    fuzzer_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        fuzzer_sock.connect((fuzzer_ip,fuzzer_port))
    except:
        print "[x.x] could not report back to fuzzer, exiting"
        sys.exit()

    if "cmdline" in sys.argv:
        cmdline_pass = True

    try:
        while True:
            
            fuzzed_input = fuzzer_sock.recv(65535)
            strlen = len(fuzzed_input)

            if cmdline_pass: 
                proc = subprocess.Popen([sys.argv[1],fuzzed_input], stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) 
                resp,err = proc.communicate()

            elif stdin:
                proc = subprocess.Popen([sys.argv[1]], stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT) 
                resp,err = proc.communicate(fuzzed_input)
        
            #log.write('[^_^] id:%d StrLen:%d retcode:%d str: %s\n\n%s\n\n'%(id, strlen,proc.returncode,repr(rand_inp),resp))
                
            #id+=1
            # 6 == sigabrt
            # 8 == sigfpe
            # 11 == sigsegv
            if proc.returncode == -11:
                buf = ''
                buf+= "------------------------------------------"
                buf+= "[x.x] Retcode:%d" %proc.returncode
                buf+= "[>_>] Strlen:%d"%(strlen) 
                buf+= "%s"%(repr(fuzzed_input)) 
                buf+= "****------------------------------------------\r\n"
                fuzzer_sock.send(buf) 
                log.write(buf)
   

    except KeyboardInterrupt:
        return
    except Exception as e:
        print e



with open('log.txt','a') as log:

    if len(sys.argv) < 2:
        print "[x.x] Usage: %s <target_proc_name>"%sys.argv[0]
        sys.exit()

    main(log) 

