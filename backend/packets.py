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
#
# Definitions for l2/l3 packet handling
#
#------------------------------------------------------------------


from ctypes import *
### L2 ###
class ETH(Structure):
    _pack_=1
    _fields_ = [
    ("ethDstU", c_uint32),
    ("ethDstL", c_uint16),
    ("ethSrcU", c_uint32),
    ("ethSrcL", c_uint16),
    ("type", c_ushort,8)
    ]
	
### L3 ###
# http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
# Just took the most used ones, if there is one missing that you need,
# take a look at above link
PROTO = { 
         "icmp":1,
         "igmp":2,
         "ipv4":4,
         "tcp":6,
         "igp":9,
         "udp":17,
         "ipv6":41,
         "ipv6-route":43,
         "ipv6-frag":44,
         "gre":47,
         "dsr":48,
         "esp":50,
         "ipv6-icmp":58,
         "ipv6-nonxt":59,
         "ipv6-opts":60,
         "eigrp":88,
         "ospf":89,
         "mtp":92,
         "l2tp":116,
         "sctp":132 
}

class IP(Structure):
    _pack_=1
    _fields_ = [
    ("version", c_ubyte,4),
    ("ihl", c_ubyte,4),
    ("tos", c_ubyte),
    ("length", c_ushort),
    ("id", c_ushort),
    ("flags", c_ubyte,3),
    ("fragOffset", c_ushort,13),
    ("ttl", c_ubyte),
    ("proto", c_ubyte),
    ("checksum", c_ushort),
    ("ipSrc", c_uint),
    ("ipDst", c_uint),
    #("options", c_uint),
    #("padding", c_ubyte * 2)
    ]

### L4 ###
class TCP(Structure):
    _fields_ = [
    ("test", c_ubyte )
    ]
    
class UDP(Structure):
    _fields_ = [
    ("test", c_ubyte )
    ]
