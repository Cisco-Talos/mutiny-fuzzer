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
# Copy this file to your project's mutiny classes directory to
# implement a long-running thread to monitor your target
# This is useful for watching files, logs, remote connections,
# PIDs, etc in parallel while mutiny is operating
# This parallel thread can signal Mutiny when it detects a crash
#
#------------------------------------------------------------------

from mutiny_classes.mutiny_exceptions import *
from time import sleep

class Monitor(object):
    # Set to True to use the monitor
    is_enabled = True
    
    # This function will run asynchronously in a different thread to monitor the host
    def monitor_target(self, target_ip, target_port, signal_main):
        # Can do something like:
        # while True:
        #   read file, etc
        #   if errorConditionHasOccurred:
        #       exception = LogCrashException('Information about the crash')
        #       exception.extra_data = 'Can add arbitrary Python objects or other data as members'
        #       signal_main(LogCrashException(exception)
        while True:
            log_file = open('./tests/assets/integration_test_1/crash.log', 'r')
            if 'crashed' in log_file.readlines():
                exception = LogCrashException('crashed')
                signal_main(LogCrashException(exception))
                signal_main(PauseFuzzingException('sleeping for 10 seconds'))
                log_file.close()
                log_file = open('./tests/assets/integration_test_1_crash.log', 'w')
                log_file.write('')
                log_file.close()
                sleep(.05)
                signal_main(ResumeFuzzingException())


            
        #
        # Calling signal_main() at any time will indicate to Mutiny
        # that the target has crashed and a crash should be logged
        #
        # Exception will be passed to exception processor
        pass
