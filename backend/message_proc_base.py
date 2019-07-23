#!/usr/bin/env python2
#------------------------------------------------------------------
# Base processor for a fuzzing session
#------------------------------------------------------------------
import errno
import socket
import thread
import struct
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
