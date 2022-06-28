#!/usr/bin/env python
#------------------------------------------------------------------
# Test serialization to ensure every char is serialized/deserialized properly
#
# Cisco Confidential
# October 2016, created within ASIG
# Author James Spadaro (jaspadar)
#
# Copyright (c) 2014-2016 by Cisco Systems, Inc.
# All rights reserved.
#
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
    
    print(("\n{}: {}{}{}\n".format(message, resultColor, resultStr, Color.END)))
    

def testString(inputValue):
    # Test the serialization function itself
    # String needs to be bytearray
    inputValue = bytearray(inputValue.encode('utf-8'))
    try:
        print(("\n{}Testing direct serialization and deserialization...{}".format(Color.BOLD, Color.END)))
        serialized = Message.serializeByteArray(inputValue)
        deserialized = Message.deserializeByteArray(serialized)
        print(("\tSerialized: {0}".format(serialized)))
        print(("\tBefore: {0}".format(inputValue.decode('utf-8'))))
        print(("\t After: {0}".format(deserialized.decode('utf-8'))))
    except Exception as e:
        print(("Caught exception running test: {}".format(str(e))))
        deserialized = ""
    printResult("Direct Serialization Test", inputValue == deserialized)

    # Also go a step further and test the inbound/outbound etc parsing
    try:
        print(("\n{}Testing full serialization with inbound/outbound lines...{}".format(Color.BOLD, Color.END)))
        message = Message()
        message.direction = Message.Direction.Outbound
        message.setMessageFrom(Message.Format.Raw, bytearray(inputValue), False)
        serialized = message.getSerialized()
        message.setFromSerialized(serialized)
        deserialized = message.getOriginalMessage()
        print(("\tSerialized: {0}".format(serialized)))
        print(("\tBefore: {0}".format(inputValue.decode('utf-8'))))
        print(("\t After: {0}".format(deserialized.decode('utf-8'))))
    except Exception as e:
        print(("Caught exception running test: {}".format(str(e))))
        deserialized = ""
    printResult("Full Serialization Test", inputValue == deserialized)

def main():
    # Try all possible ASCII characters
    allchars = 'datadatadata unprintable chars:'
    for i in range (0, 256):
        allchars += chr(i)
    testString(allchars)
    
    # Added as a result of issue #2 in git
    # Strings that contain only single quotes apparently get wrapped in double quotes
    testString("test'")

    # Found to be causing problems
    testString("<?xml version='1.0' ?><stream:stream to='testwebsite.com' xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' version='1.0'>")
    
if __name__ == "__main__":
    main()
