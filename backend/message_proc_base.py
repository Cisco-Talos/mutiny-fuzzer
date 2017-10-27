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
#------------------------------------------------------------------
# Base processor for a fuzzing session
#------------------------------------------------------------------
import errno
import socket
import thread
from mutiny_classes.mutiny_exceptions import *

class MessageProcessor(object):
    def __init__(self):
        self.postReceiveStore = {}
    
    # runNumber = number of current run
    # targetIP = address to connect to
    # targetPort = port being connected to
    # Called when the fuzzer is about to connect for runNumber
    def preConnect(self, runNumber, targetIP, targetPort):
        pass
    
    # subcomponent = subcomponent of message about to be fuzzed
    # Will not be called if message has no subcomponents
    # allSubcomponents are included for reference (list of subcomponent data)
    # Return subcomponent with any required modifications made
    def preFuzzSubcomponentProcess(self, subcomponent, allSubcomponents):
        return subcomponent
    
    # message = full message about to be fuzzed
    # ONLY called if message has no subcomponents
    # If you use subcomponents, handle in preFuzzSubcomponentProcess()
    # Return message with any required modifications made
    def preFuzzProcess(self, message):
        return message

    # subcomponent = subcomponent of message about to be sent
    # Will not be called if message has no subcomponents
    # allSubcomponents are included for reference (list of subcomponent data)
    # Return subcomponent with any required modifications made
    # If subcomponent was fuzzed, this is the post-fuzzing subcomponent
    def preSendSubcomponentProcess(self, subcomponent, allSubcomponents):
        return subcomponent
    
    # message = full message about to be sent
    # Any fuzzing on this message has been performed by this point
    # Called after preSendSubcomponentProcess() is called for every subcomponent,
    # if applicable
    # Return message with any required modifications made
    def preSendProcess(self, message):
        return message

    # message = message that was actually received
    # expectedMessage = what the message should have been based on pcap
    # messageNumber = the number in the conversation
    # Does not return anything
    # Can store messages for later use in the class as shown
    def postReceiveProcess(self, message, expectedMessage, messageNumber):
        self.postReceiveStore[int(messageNumber)] = message
