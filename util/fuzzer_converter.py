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
# Convert .fuzzer messages to binary/ascii and vice-versa
#------------------------------------------------------------------

import argparse
import os.path
import sys
import re

# Kind of dirty, grab libs from one directory up
sys.path.insert(0, os.path.abspath( os.path.join(__file__, "../..")))
from backend.fuzzerdata import FuzzerData
from backend.fuzzer_types import Message

epilog = """Actions: 
fuzzer2bin - Pull binary message out of .fuzzer file
bin2fuzzer - Update message in .fuzzer file with raw binary data
list       - List all messages in a .fuzzer
"""
parser = argparse.ArgumentParser(description="Script to convert and view .fuzzer data", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=epilog)
parser.add_argument("action", help="Action to use, see below", choices=["fuzzer2bin", "bin2fuzzer", "list"])
parser.add_argument("-i", "--infile", help="File to read input from, uses stdin otherwise")
parser.add_argument("-o", "--outfile", help="File to write results to, uses stdout otherwise")
parser.add_argument("-f", "--fuzzerfile", help="File to get .fuzzer data from for bin2fuzzer, if it should differ from outfile or outfile is stdout")
parser.add_argument("-m", "--messagenum", help="Message number to read/write (fuzzer2bin and bin2fuzzer)", type=int)
args = parser.parse_args()

if args.action != "bin2fuzzer" and args.fuzzerfile:
    print("Use --fuzzerfile with only the bin2fuzzer option, to populate .fuzzer data")
    exit(1)

# Default file descriptors
inFileDesc = sys.stdin
outFileDesc = sys.stdout 

# If we get file paths instead, fix them up
if args.infile:
    inFileDesc = open(args.infile, "r")
if args.outfile:
    outFileDesc = open(args.outfile, "w")

if args.action == "list":
    fuzzerData = FuzzerData()
    # Allow a non-quiet read to list out messages
    fuzzerData.readFromFD(inFileDesc, quiet=False)
    
elif args.action in ["fuzzer2bin", "bin2fuzzer"]:
    if args.messagenum == None:
        print("Message number required for action {0}".format(args.action))
        exit(1)

    fuzzerData = FuzzerData()
    
    if args.action == "fuzzer2bin":
        # Pull message out from .fuzzer file, output as binary
        fuzzerData.readFromFD(inFileDesc, quiet=True)
        
        messageCount = len(fuzzerData.messageCollection.messages)
        if args.messagenum < 0 or args.messagenum >= messageCount:
            print("Message number out of range: {0}".format(args.messagenum))
            exit(1)
        
        outFileDesc.write(fuzzerData.messageCollection.messages[args.messagenum].getOriginalMessage())
    elif args.action == "bin2fuzzer":
        if not args.outfile and not args.fuzzerfile:
            print("outfile or fuzzerfile required for action {0}".format(args.action))
        
        if args.fuzzerfile:
            fuzzerData.readFromFile(args.fuzzerfile, quiet=True)
        else:
            try:
                # readFromFile() since outFileDesc is opened for write
                fuzzerData.readFromFile(args.outfile, quiet=True)
            except Exception as ex:
                print("Ignoring bad outfile, writing default .fuzzer data, error: {0}".format(str(ex)))
                pass
        
        messageData = bytearray()
        for line in inFileDesc:
            messageData += line

        messageCount = len(fuzzerData.messageCollection.messages)
        if args.messagenum < 0 or args.messagenum >= messageCount:
            print("Message number out of range: {0}".format(args.messagenum))
            exit(1)
        message = fuzzerData.messageCollection.messages[args.messagenum]
        message.setMessageFrom(Message.Format.Raw, messageData, message.isFuzzed)
        fuzzerData.writeToFD(outFileDesc)

# Clean up file descriptors
if args.infile:
    inFileDesc.close()
if args.outfile:
    outFileDesc.close()
