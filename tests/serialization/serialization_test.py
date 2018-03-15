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
# Test serialization to ensure every char is serialized/deserialized properly
#------------------------------------------------------------------

import sys
sys.path.append("../..")
from backend.fuzzer_types import Message

class Color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def printResult(message, isPass):
    if isPass:
        resultStr = "Pass"
        resultColor = Color.GREEN
    else:
        resultStr = "Fail"
        resultColor = Color.RED
    
    print("\n{}: {}{}{}\n".format(message, resultColor, resultStr, Color.END))
    

def testString(inputValue):
    # Test the serialization function itself
    try:
        print("\n{}Testing direct serialization and deserialization...{}".format(Color.BOLD, Color.END))
        serialized = Message.serializeByteArray(inputValue)
        deserialized = Message.deserializeByteArray(serialized)
        print("\tSerialized: {0}".format(serialized))
        print("\tBefore: {0}".format(str(inputValue)))
        print("\t After: {0}".format(str(deserialized)))
    except Exception as e:
        print("Caught exception running test: {}".format(str(e)))
        deserialized = ""
    printResult("Direct Serialization Test", inputValue == deserialized)

    # Also go a step further and test the inbound/outbound etc parsing
    try:
        print("\n{}Testing full serialization with inbound/outbound lines...{}".format(Color.BOLD, Color.END))
        message = Message()
        message.direction = Message.Direction.Outbound
        message.appendMessageFrom(Message.Format.Raw, bytearray(inputValue), attributes="")
        serialized = message.getSerialized()
        # setFromSerialized() calls append in this old version - fixed in new Master,
        # but not yet merged to this branch
        message = Message()
        message.direction = Message.Direction.Outbound
        message.setFromSerialized(serialized)
        deserialized = message.getOriginalMessage()
        print("\tBefore: {0}".format(str(inputValue)))
        print("\t After: {0}".format(str(deserialized)))
    except Exception as e:
        print("Caught exception running test: {}".format(str(e)))
        deserialized = ""
    printResult("Full Serialization Test", inputValue == deserialized)

def main():
    # Try all possible ASCII characters
    allchars = bytearray('datadatadata unprintable chars:')
    for i in range (0, 256):
        allchars += chr(i)
    testString(allchars)
    
    # Added as a result of issue #2 in git
    # Strings that contain only single quotes apparently get wrapped in double quotes
    testString("test'")

if __name__ == "__main__":
    main()
