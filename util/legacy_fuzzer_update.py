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
# Update .fuzzer files from old version to new version. 
# More than likely, you won't need to use this, as the old version
# was removed before release. 
#------------------------------------------------------------------
import os.path
import sys
import re

# Kind of dirty, grab libs from one directory up
sys.path.insert(0, os.path.abspath( os.path.join(__file__, "../..")))
from backend.fuzzerdata import FuzzerData
from backend.fuzzer_types import Message

def main():

    try:
        fuzz_data = FuzzerData()
        old_fuzzer = sys.argv[-1] 
        new_fuzzer = old_fuzzer + ".new"
    except Exception as e:
        usage()

    try:
        print "[>_>] Attempting to read: %s, writing to %s"%(old_fuzzer,new_fuzzer)
        fuzz_data.readFromFile(old_fuzzer)
        fuzz_data.writeToFile(new_fuzzer)
        print "[^_^] All done!"
    except Exception as e:
        print "[x_x] %s" % str(e)

def usage():
    print "Usage: python legacy_fuzzer_update.py <input_file>"
    sys.exit()

if __name__ == "__main__":
    main()


