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
# Type definitions for the fuzzer
# This script defines the various message and data types used in
# the fuzzer, and utility functions used by them.
#------------------------------------------------------------------
from datetime import datetime

class MessageSubComponent(object):
    def __init__(self, message, attributes):
        self.attributes = attributes
        self.message = message
        self.isFuzzed = False

        if 'fuzz' in self.attributes: 
            self.isFuzzed = True
        
        self.fixedSize = -1
        if "fixedSize" in self.attributes:
            self.fixedSize = len(message)
 
        # This includes both fuzzed messages and messages the user
        # has altered with messageprocessor callbacks
        self._altered = message
    
    def setAlteredByteArray(self, byteArray):
        self._altered = byteArray
    
    def getAlteredByteArray(self):
        return self._altered

# Contains all data of a given packet of the session. Does not actually hold any 
# strings itself, its essentially a container for a <1,2,..,N> submessages.            
class Message(object):

    class Direction:
        Outbound = "outbound"
        Inbound ="inbound"

    class Format:
        CommaSeparatedHex = 0 # 00,01,02,20,2a,30,31
        Ascii = 1 # asdf\x00\x01\x02
        Raw = 2 # a raw byte array from a pcap
        
    def __init__(self):
        self.attributes = []
        self.direction = -1
        # Submessages have their own attributes/fuzzed/etc. Whereas linebreaks don't.  
        # outbound 'msg'
        #          'moreMessge'
        # sub fuzz 'msg'
        # If it's a traditional message, it will only have one element (entire message)
        self.subcomponents = []

    def getOriginalSubcomponents(self):
        return map(lambda subcomponent: subcomponent.message, self.subcomponents)
    
    # May or may not have actually been changed
    # Version of subcomponents that includes fuzzing and messageprocessor changes from user
    # Is transient and reverted to original every iteration
    def getAlteredSubcomponents(self):
        return map(lambda subcomponent: subcomponent.getAlteredByteArray(), self.subcomponents)
    
    def getOriginalMessage(self):
        return bytearray().join(map(lambda subcomponent: subcomponent.message, self.subcomponents))
    
    # May or may not have actually been changed
    # Version of message that includes fuzzing and messageprocessor changes from user
    # Is transient and reverted to original every iteration
    def getAlteredMessage(self):
        return bytearray().join(map(lambda subcomponent: subcomponent.getAlteredByteArray(), self.subcomponents))
    
    def resetAlteredMessage(self):
        for subcomponent in self.subcomponents:
            subcomponent.setAlteredByteArray(subcomponent.message)
    
    # Same arguments as above, but adds to .message as well as
    # adding a new subcomponent
    # createNewSubcomponent - If false, don't create another subcomponent,
    #   instead, append new message data to last subcomponent in message
    def appendMessageFrom(self, sourceType, message, attributes, createNewSubcomponent=True):
        if sourceType == self.Format.CommaSeparatedHex:
            newMessage = bytearray(map(lambda x: x.decode("hex"), message.split(",")))
        elif sourceType == self.Format.Ascii:
            newMessage = self.deserializeByteArray(message)
        elif sourceType == self.Format.Raw:
            newMessage = message
        else:
            raise RuntimeError("Invalid sourceType")
        
        if createNewSubcomponent:
            self.subcomponents.append(MessageSubComponent(newMessage, attributes))
        else:
            self.subcomponents[-1].message += newMessage
    
    def isOutbound(self):
        return self.direction == self.Direction.Outbound
    
    def __eq__(self, other):
        # bytearray (for message) implements __eq__()
        return self.direction == other.direction and self.message == other.message
    
    @classmethod
    def serializeByteArray(cls, byteArray):
        # repr() appears to do exactly what we want here
        return repr(str(byteArray))
    
    @classmethod
    def deserializeByteArray(cls, string):
        # This appears to properly reverse repr() without the risks of eval
        tmp = bytearray(string[1:-1].decode('string_escape'))
        return tmp
    
    def getAlteredSerialized(self):
        if len(self.subcomponents) < 1:
            return "{0} {1}\n".format(self.direction, "ERROR: No data in message.")
        else:
            serializedMessage = "{0}{1} {2}\n".format("fuzz " if self.subcomponents[0].isFuzzed else "", self.direction, self.serializeByteArray(self.subcomponents[0].getAlteredByteArray()))
            
            for subcomponent in self.subcomponents[1:]:
                serializedMessage += "more {0}{1}\n".format("fuzz " if subcomponent.isFuzzed else "", self.serializeByteArray(subcomponent.getAlteredByteArray()))
            
            return serializedMessage
    
    def getSerialized(self):
        if len(self.subcomponents) < 1:
            return "{0} {1}\n".format(self.direction, "ERROR: No data in message.")
        else:
            serializedMessage = "{0} {1}{2}\n".format(self.direction, "fuzz " if self.subcomponents[0].isFuzzed else "", self.serializeByteArray(self.subcomponents[0].message))
            
            for subcomponent in self.subcomponents[1:]:
                serializedMessage += "more {0}{1}\n".format("fuzz " if subcomponent.isFuzzed else "", self.serializeByteArray(subcomponent.message))
            
            return serializedMessage

    # Utility function for setFromSerialized and appendFromSerialized below
    def _extractMessageComponents(self, serializedData):
        # Just assume everything from the first single quote to the end is the message
        firstQuote = serializedData.find("'")
        if firstQuote == -1:
            raise RuntimeError("Invalid message data, no message found")
        # Pull out everything, quotes and all, and deserialize it
        messageData = serializedData[firstQuote:]
        # Process the args
        serializedData = serializedData[:firstQuote].split(" ")
        
        return (serializedData, messageData)
    
    # Handles _one line_ of data, either "inbound" or "outbound"
    # Lines following this should be passed to appendFromSerialized() below
    def setFromSerialized(self, serializedData):
        serializedData = serializedData.replace("\n", "")
        (serializedData, messageData) = self._extractMessageComponents(serializedData)
        
        if len(messageData) == 0 or len(serializedData) < 1:
            raise RuntimeError("Invalid message data")
        
        direction = serializedData[0]
        attrs = serializedData[1:-1]

        if direction != "inbound" and direction != "outbound":
            raise RuntimeError("Invalid message data, unknown direction {0}".format(direction))
        
        self.direction = direction
        self.appendMessageFrom(self.Format.Ascii, messageData, attrs)
    
    # Add another line, used for multiline messages
    def appendFromSerialized(self, serializedData):
        # there shouldn't be any newlines...
        # serializedData = serializedData.replace("\n", "")
        (serializedData, messageData) = self._extractMessageComponents(serializedData)
        
        if len(messageData) == 0 or len(serializedData) < 1 or serializedData[0] != "more":
            raise RuntimeError("Invalid message data")
        
        attrs = serializedData[1:-1]
        self.appendMessageFrom(self.Format.Ascii, messageData, attrs)


class MessageCollection(object):
    def __init__(self):
        self.messages = []
    
    def addMessage(self, message):
        self.messages.append(message)
    
    def doClientMessagesMatch(self, otherMessageCollection):
        for i in range(0, len(self.messages)):
            # Skip server messages
            if not self.messages[i].isOutbound():
                continue
            try:
                # Message implements __eq__()
                if self.messages[i] != otherMessageCollection.messages[i]:
                    return False
            except IndexError:
                return False
        
        # All messages passed
        return True

    def __getitem__(self,i):
        return self.messages[i]

import os
import os.path
from copy import deepcopy

# Handles all the logging of the fuzzing session
# Log messages can be found at sample_apps/<app>/<app>_logs/<date>/
class Logger(object):
    def __init__(self, folderPath):
        self._folderPath = os.path.join(folderPath,str(datetime.now()))
        if not os.path.isdir(self._folderPath):
            try:
                os.makedirs(self._folderPath)
            except:
                pass

        self.resetForNewRun()

    def setReceivedMessages(self, messageNumber, data):
        message = Message()
        message.direction = Message.Direction.Outbound
        message.message = data
        self.receivedMessages[messageNumber] = message

    def setHighestMessageNumber(self, messageNumber):
        # The highest message # this fuzz session made it to
        self._highestMessageNumber = messageNumber

    def outputLastLog(self, runNumber, messageCollection, errorMessage, messagesToFuzz):
        return self._outputLog(runNumber, messageCollection, errorMessage, messagesToFuzz, self._lastReceivedMessages, self._lastHighestMessageNumber)
    def logSimple(self,msg):
        with open(os.path.join(self._folderPath, "output_log.txt"), "a") as outputFile:
            time = str(datetime.now())
            outputFile.write("%s| %s\n"%(time,msg))

    def outputLog(self, runNumber, messageCollection, errorMessage, messagesToFuzz):
        return self._outputLog(runNumber, messageCollection, errorMessage, messagesToFuzz, self.receivedMessages, self._highestMessageNumber)

    def _outputLog(self, runNumber, messageCollection, errorMessage, messagesToFuzz, receivedMessages, highestMessageNumber):
        with open(os.path.join(self._folderPath, str(runNumber)), "w") as outputFile:
            print "Logging run number %d" % (runNumber)
            outputFile.write("Log from run with seed %d\n" % (runNumber))
            outputFile.write("Error message: %s\n" % (errorMessage))

            if highestMessageNumber == -1 or runNumber == 0:
                outputFile.write("Failed to connect on this run.\n")

            outputFile.write("\n")

            i = 0
            for message in messageCollection.messages:
                outputFile.write("Packet %d: %s" % (i, message.getSerialized()))

                if i in messagesToFuzz:
                    outputFile.write("Fuzzed Packet %d: %s\n" % (i, message.getFuzzedSerialized()))

                if receivedMessages.has_key(i):
                    # Compare what was actually sent to what we expected, log if they differ
                    if receivedMessages[i].message != message.message:
                        outputFile.write("Actual data received for packet %d: %s" % (i, receivedMessages[i].getSerialized()))
                    else:
                        outputFile.write("Received expected data\n")

                if highestMessageNumber == i:
                    if message.isOutbound():
                        outputFile.write("This is the last message sent\n")
                    else:
                        outputFile.write("This is the last message received\n")

                outputFile.write("\n")
                i += 1

    def resetForNewRun(self):
        try:
            self._lastReceivedMessages = deepcopy(self.receivedMessages)
            self._lastHighestMessageNumber = self._highestMessageNumber
        except AttributeError:
            self._lastReceivedMessages = {}
            self._lastHighestMessageNumber = -1

        self.receivedMessages = {}
        self.setHighestMessageNumber(-1)
