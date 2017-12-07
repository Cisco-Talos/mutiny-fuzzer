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

def main():
    allchars = bytearray('datadatadata unprintable chars:')
    for i in range (0, 256):
        allchars += chr(i)
    
    print("Testing serialization and deserialization...")
    serialized = Message.serializeByteArray(allchars)
    deserialized = Message.deserializeByteArray(serialized)
    print("Serialized: {0}".format(serialized))
    print("Before: {0}".format(str(allchars)))
    print(" After: {0}".format(str(deserialized)))
    
    print("Test: {0}".format("pass" if allchars == deserialized else "fail"))

if __name__ == "__main__":
    main()
