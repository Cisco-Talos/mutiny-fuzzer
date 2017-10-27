#!/usr/bin/env python
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

import sys
import argparse
from scapy.all import *

def main():

    if len(sys.argv) < 2:
        sys.argv.append('-h') 

    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="pcap to dump")
    parser.add_argument("-f", "--filename", help="file to write to") 
    args = parser.parse_args()

    pcap = rdpcap(args.pcap)

    try:
        srcPort = pcap[0][TCP].sport
    except:
        srcPort = pcap[0][UDP].sport

    src = ( pcap[0][Ether].src, pcap[0][IP].src, srcPort) 

    retbuff = []
    for packet in pcap:
        # skip packets without data (syn/ack/synack)
        try:
            len(packet[Raw])
        except IndexError:
            continue
            
        tmp = ""
        if isSrc(src,packet): 
            try:
                for byte in str(packet[Raw]):
                    tmp+="\\x0" if ord(byte) <= 0xf else "\\x"  
                    tmp+=hex(ord(byte))[2:] 
            except IndexError:
                pass
            if tmp:
                retbuff.append("send(\"" + tmp + "\")")
        
        #recv(1024) data sent by server, don't really care what it is         
        else: 
            retbuff.append("recv(1024)") if len(packet) < 1024 else retbuff.append("recv(%d)" % len(packet))
    
    if args.filename:
        with open(args.filename,'w') as f: 
            for packet in retbuff:
                f.write(packet + "\n")
    else:
        for packet in retbuff:
            print packet
 
def isSrc(srcInfo,packet):   
    # info_tuple[0] = [Ether].src
    # info_tuple[1] = [IP].src
    # info_tuple[2] = [TCP/UDP].sport
    try:
        l4port = packet[TCP].sport
    except:
        l4port = packet[TCP].sport
      
    try:
        if packet[Ether].src == srcInfo[0] and packet[IP].src == srcInfo[1] and l4port == srcInfo[2]: 
            return 1 
    except:
        pass 

    return 0


if __name__ == "__main__":
    main()
