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
# Processor for a fuzzing session
#
# Copy this file to your project's mutiny classes directory to
# change message processing
# This is useful to alter fuzzed messages before transmission,
# such as updating outbound messages based on the server's responses
#
#------------------------------------------------------------------

import errno
import socket
import _thread
from mutiny_classes.mutiny_exceptions import *

# This class is used to provide extra parameters beyond only the message
# contents to the MessageProcessor callbacks 
# Do not bother this here, as only the base mutiny_classes version will get
# imported by design
class MessageProcessorExtraParams(object):
    def __init__(self, messageNumber, subcomponentNumber, isFuzzed, originalSubcomponents, actualSubcomponents):
        # Which message number this is in the .fuzzer file list, 0-indexed
        self.messageNumber = messageNumber
        
        # Which subcomponent is being called within this specific callback
        # Is -1 if it doesn't apply (examples: preFuzzProcess/preSendProcess/postReceiveProcess)
        self.subcomponentNumber = subcomponentNumber

        # Will message / subcomponent be fuzzed?
        self.isFuzzed = isFuzzed
        
        # List of subcomponent data as they are recorded in the .fuzzer file
        self.originalSubcomponents = originalSubcomponents
        
        # List of subcomponent data as it was actually received or will be
        # transmitted after fuzzing
        self.actualSubcomponents = actualSubcomponents

        # Convenience variable that is literally just all the originalSubcomponents combined
        self.originalMessage = bytearray().join(self.originalSubcomponents)
        
        # Convenience variable that is literally just all the actualSubcomponents combined
        self.actualMessage = bytearray().join(self.actualSubcomponents)

class MessageProcessor(object):
    def __init__(self):
        self.postReceiveStore = {}
    
    # runNumber = number of current run
    # targetIP = address to connect to
    # targetPort = port being connected to
    # Called when the fuzzer is about to connect for runNumber
    def preConnect(self, runNumber, targetIP, targetPort):
        pass
    
    # subcomponent = subcomponent of message
    # Called whether or not subcomponent will be fuzzed
    # Will not be called if message has no subcomponents
    # extraParams contains MessageProcessorExtraParams based on the Message this
    # is a subcomponent for
    # Return subcomponent with any required modifications made
    def preFuzzSubcomponentProcess(self, subcomponent, extraParams):
        return subcomponent
    
    # message = full message, called whether or not message will be fuzzed
    # ONLY called if message has no subcomponents
    # If you use subcomponents, handle in preFuzzSubcomponentProcess()
    # extraParams contains MessageProcessorExtraParams based on this Message
    # Return message with any required modifications made
    def preFuzzProcess(self, message, extraParams):
        return message

    # subcomponent = subcomponent of message about to be sent
    # Will not be called if message has no subcomponents
    # extraParams contains MessageProcessorExtraParams based on the Message this
    # is a subcomponent for
    # Return subcomponent with any required modifications made
    # If subcomponent was fuzzed, this is the post-fuzzing subcomponent
    def preSendSubcomponentProcess(self, subcomponent, extraParams):
        return subcomponent
    
    # message = full message about to be sent
    # Any fuzzing on this message has been performed by this point
    # Called after preSendSubcomponentProcess() is called for every subcomponent,
    # if applicable
    # extraParams contains MessageProcessorExtraParams based on this Message
    # Return message with any required modifications made
    def preSendProcess(self, message, extraParams):
        return message

    # message = message that was actually received
    # extraParams contains MessageProcessorExtraParams based on this Message
    # Does not return anything
    # Can store messages for later use in the class as shown
    def postReceiveProcess(self, message, extraParams):
        self.postReceiveStore[int(extraParams.messageNumber)] = message
