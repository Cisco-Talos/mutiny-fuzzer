#!/usr/bin/env python
#------------------------------------------------------------------
# Base processor for a fuzzing session
#
# Cisco Confidential
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Contributor Lilith Wyatt (liwyatt)
#
# Copyright (c) 2014-2015 by Cisco Systems, Inc.
# All rights reserved.
#
# This script is the base class for the MessageProcessor 
# Create a message_processor.py file into your project's subfolder
# File will be imported into mutiny.py. 
#------------------------------------------------------------------

# Copy this file to your project's mutiny classes directory to
# change message processing
# This is useful to alter fuzzed messages before transmission,
# such as updating outbound messages based on the server's responses

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

        # if message indicates fault, raise LogCrashException("reason")
        if extraParams.messageNumber == 3:
            if len(message) == 0 or (message != bytearray("OK\n") and message != bytearray("INVALID\n")):
                print(message)
                raise LogCrashException("Server response was not OK or INVALID")
