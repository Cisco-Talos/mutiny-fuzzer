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
# This is used in the exploit generation feature ('-x' switch)
# of Mutiny. Change it if you want a different base exploit.
# Or not, w/e. (>_>) 
#------------------------------------------------------------------
import socket
import struct
import sys

IP = "%s"
PORT = %d 
timeout = .3
strLen = 200
#colors
RED='\033[31m'
ORANGE='\033[91m'
GREEN='\033[92m'
LIME='\033[99m'
YELLOW='\033[93m'
BLUE='\033[94m'
PURPLE='\033[95m'
CYAN='\033[96m'
CLEAR='\033[00m'



# each entry in packet list should be:
# (0, msg) or (1,msg) for the direction
packet_list = %s
 
def main():
    tmp = ""

    
    try:
        if ":" in IP:
            sock = socket.socket(socket.AF_INET6,socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.connect((IP,PORT))
        sock.settimeout(timeout)
    except:
        print "[x.x] No connect to " + IP +":" + str(PORT) 

        sys.exit()
    
    count = 0
    outbuff = ""
    for direction,packet in packet_list:
        
        #print "\033[96mDirection:" + str(inbound) + ",Packet#:" + str(count) + "\033[00m - " + repr(packet)
        count+=1
        if direction == "inbound": 

            if len(outbuff):
                #print "[!.1] " + repr(outbuff)
                sock.send(outbuff)
                outbuff = ""

            tmp = ""
            while True:
                try:
                    tmp += sock.recv(65535)
                    if len(tmp):
                        break
                except KeyboardInterrupt:
                    print RED + "[;_;] You killed me." + CLEAR
                    sys.exit()
                    
                except:
                    break

            if tmp:
                try:
                    print YELLOW + "[<.<] " + repr(tmp[0:strLen]) + CLEAR
                except:
                    print YELLOW + "[<.<] " + repr(tmp) + CLEAR
                if len(tmp) > strLen: 
                    print "[...]"

        elif direction == "outbound": 
            if len(packet) > strLen: 
                print PURPLE + "[>.>] " + repr(packet[0:strLen]) + "[...]" + CLEAR
            else:
                print PURPLE + "[>.>] " + repr(packet) + CLEAR
            outbuff += packet
            
    
    if direction == "inbound":
        tmp = ""
        try:
            while True:
                try:
                    tmp += sock.recv(65535)
                except:
                    break

            if len(tmp):
                print YELLOW + "[!_!] Final Resp:\n" + repr(tmp) + CLEAR
            else:
                print RED + "[;_;] No resp...." + CLEAR
        except KeyboardInterrupt:
            print RED + "[;_;] You killed me." + CLEAR
            
    elif direction == "outbound":
        sock.send(outbuff)

    print "[^_^] Thanks for stopping by~"



if __name__ == "__main__":
    main()
