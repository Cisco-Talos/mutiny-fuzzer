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
# Class to hold fuzzer data (.fuzzer file info)
# Can read/write .fuzzer files from an instantiation
#
#------------------------------------------------------------------

from backend.fuzzer_types import MessageCollection, Message
from backend.menu_functions import validateNumberRange
import os.path
import sys

class FuzzerData(object):
    # Init creates fuzzer data and populates with defaults
    # readFromFile to load a .fuzzer file
    def __init__(self):
        # All messages in the conversation
        self.messageCollection = MessageCollection()
        # Directory containing custom processors (Exception, Message, Monitor)
        # or "default"
        self.processorDirectory = "default"
        # Number of times a test case causing a crash should be repeated
        self.failureThreshold = 3
        # How long to wait between retests
        self.failureTimeout = 5
        # Protocol (TCP, UDP)
        self.proto = "tcp"
        # Port to use
        self.port = 0
        # Source port to use, -1 = auto
        self.sourcePort = -1
        # Source IP to use, 0.0.0.0 or "" is default/automatic
        self.sourceIP = "0.0.0.0"
        # Whether to perform a test run
        self.shouldPerformTestRun = True
        # How long to time out on receive() (seconds)
        self.receiveTimeout = 1.0
        # Dictionary to save comments made to a .fuzzer file.  Only really does anything if 
        # using readFromFile and then writeToFile in the same program
        # (For example, fuzzerconverter)
        self.comments = {}
        # Kind of kludgy string for use in readFromFD, made global to not have to pass around
        # Details in readFromFD()
        self._readComments = ""
        # Update for compatibilty with new Decept
        self.messagesToFuzz = [] 
    
    
    # Read in the FuzzerData from the specified .fuzzer file
    def readFromFile(self, filePath, quiet=False):
        with open(filePath, 'r') as inputFile:
            self.readFromFD(inputFile, quiet=quiet)
    
    # Utility function to fix up self.comments and self._readComments within readFromFD()
    # as data is read in
    def _pushComments(self, commentSectionName):
        self.comments[commentSectionName] = self._readComments
        self._readComments = ""

    # Same as above, but appends to existing comment section if possible
    def _appendComments(self, commentSectionName):
        if commentSectionName in self.comments:
            self.comments[commentSectionName] += self._readComments
        else:
            self.comments[commentSectionName] = self._readComments
        self._readComments = ""

    # Update for compatibilty with newer versions of Decept.
    
    
    # Read in the FuzzerData from a specific file descriptor
    # Most usefully can be used to read from stdout by passing
    # sys.stdin
    def readFromFD(self, fileDescriptor, quiet=False):
        messageNum = 0
        
        # This is used to track multiline messages
        lastMessage = None
        # Build up comments in this string until we're ready to push them out to the dictionary
        # Basically, we build lines and lines of comments, then when a command is encountered,
        # push them into the dictionary using that command as a key
        # Thus, when we go to write them back out, we can print them all before a given key
        self._readComments = ""
        
        for line in fileDescriptor:
            # Record comments on read so we can play them back on write if applicable
            if line.startswith("#") or line == "\n":
                self._readComments += line
                # Skip all further processing for this line
                continue
            
            line = line.replace("\n", "")
            
            # Skip comments and whitespace
            if not line.startswith("#") and not line == "" and not line.isspace():
                args = line.split(" ")
                
                # Populate FuzzerData obj with any settings we can parse out
                try:
                    if args[0] == "processor_dir":
                        self.processorDirectory = args[1]
                        self._pushComments("processor_dir")
                    elif args[0] == "failureThreshold":
                        self.failureThreshold = int(args[1])
                        self._pushComments("failureThreshold")
                    elif args[0] == "failureTimeout":
                        self.failureTimeout = int(args[1])
                        self._pushComments("failureTimeout")
                    elif args[0] == "proto":
                        self.proto = args[1]
                        self._pushComments("proto")
                    elif args[0] == "port":
                        self.port = int(args[1])
                        self._pushComments("port")
                    elif args[0] == "sourcePort":
                        self.sourcePort = int(args[1])
                        self._pushComments("sourcePort")
                    elif args[0] == "sourceIP":
                        self.sourceIP = args[1]
                        self._pushComments("sourceIP")
                    elif args[0] == "shouldPerformTestRun":
                        # Use 0 or 1 for setting
                        if args[1] == "0":
                            self.shouldPerformTestRun = False
                        elif args[1] == "1":
                            self.shouldPerformTestRun = True
                        else:
                            raise RuntimeError("shouldPerformTestRun must be 0 or 1")
                        self._pushComments("shouldPerformTestRun")
                    elif args[0] == "receiveTimeout":
                        self.receiveTimeout = float(args[1])
                        self._pushComments("receiveTimeout")
                    elif args[0] == "messagesToFuzz":
                        print("WARNING: It looks like you're using a legacy .fuzzer file with messagesToFuzz set.  This is now deprecated, so please update to the new format")
                        self.messagesToFuzz = validateNumberRange(args[1], flattenList=True)
                        # Slight kludge: store comments above messagesToFuzz with the first message.  *shrug*
                        # Comment saving is best effort anyway, right?
                        self._pushComments("message0")
                    elif args[0] == "unfuzzedBytes":
                        print("ERROR: It looks like you're using a legacy .fuzzer file with unfuzzedBytes set.  This has been replaced by the new multi-line format.  Please update your .fuzzer file.")
                        sys.exit(-1)
                    elif args[0] == "inbound" or args[0] == "outbound":
                        message = Message()
                        message.setFromSerialized(line)
                        self.messageCollection.addMessage(message)
                        # Legacy code to handle old messagesToFuzz format
                        if messageNum in self.messagesToFuzz:
                            message.isFuzzed = True
                        if not quiet:
                            print("\tMessage #{0}: {1} bytes {2}".format(messageNum, len(message.getOriginalMessage()), message.direction))
                        self._pushComments("message{0}".format(messageNum))
                        messageNum += 1
                        lastMessage = message
                    # "sub" means this is a subcomponent
                    elif args[0] == "sub":
                        if not 'message' in locals():
                            print("\tERROR: 'sub' line declared before any 'message' lines, throwing subcomponent out: {0}".format(line))
                        else:
                            message.appendFromSerialized(line)
                            if not quiet:
                                print("\t\tSubcomponent: {1} additional bytes".format(messageNum, len(message.subcomponents[-1].message)))
                    elif line.lstrip()[0] == "'" and 'message' in locals():
                        # If the line begins with ' and a message line has been found,
                        # assume that this is additional message data
                        # (Different from a subcomponent because it can't have additional data 
                        # tacked on)
                        message.appendFromSerialized(line.lstrip(), createNewSubcomponent=False)
                    else:
                        if not quiet:
                            print("Unknown setting in .fuzzer file: {0}".format(args[0]))
                    # Slap any messages between "message" and "sub", etc (ascii same way) above message
                    # It's way too annoying to print these out properly, as they get
                    # automagically outserialized by the Message object
                    # Plus they may change... eh, forget it, user can fix up themselves if they want
                    self._appendComments("message{0}".format(messageNum-1))
                except Exception as e:
                    print("Invalid line: {0}".format(line))
                    raise e
        # Catch any comments below the last line
        self._pushComments("endcomments")
                        
    # Utility function to get comments for a section after checking if they exist
    # If not, returns ""
    def _getComments(self, commentSectionName):
        if commentSectionName in self.comments:
            return self.comments[commentSectionName]
        else:
            return ""

    # Set messagesToFuzz from string (such as "1,3-4")
    def setMessagesToFuzzFromString(self, messagesToFuzzStr):
        self.messagesToFuzz = validateNumberRange(messagesToFuzzStr, flattenList=True)
        #print self._messagesToFuzz

    
    # Write out the FuzzerData to the specified .fuzzer file
    def writeToFile(self, filePath, defaultComments=False, finalMessageNum=-1):
        origFilePath = filePath
        tail = 0
        while os.path.isfile(filePath):
            tail += 1
            filePath = "{0}-{1}".format(origFilePath, tail)
            # print "File %s already exists" % (filePath,)
        
        if origFilePath != filePath:
            print(("File {0} already exists, using {1} instead".format(origFilePath, filePath)))

        with open(filePath, 'w') as outputFile:
            self.writeToFD(outputFile, defaultComments=defaultComments, finalMessageNum=finalMessageNum)
        
        return filePath

    # Write out the FuzzerData to a specific file descriptor
    # Most usefully can be used to write to stdout by passing
    # sys.stdout
    def writeToFD(self, fileDescriptor, defaultComments=False, finalMessageNum=-1):
        if not defaultComments and "start" in self.comments:
            fileDescriptor.write(self.comments["start"])
        
        # Processor Directory
        if defaultComments:
            comment = "# Directory containing any custom exception/message/monitor processors\n"
            comment += "# This should be either an absolute path or relative to the .fuzzer file\n"
            comment += "# If set to \"default\", Mutiny will use any processors in the same\n"
            comment += "# folder as the .fuzzer file\n"
            fileDescriptor.write(comment)
        else:
            fileDescriptor.write(self._getComments("processor_dir"))
        fileDescriptor.write("processor_dir {0}\n".format(self.processorDirectory))
        
        # Failure Threshold
        if defaultComments:
            fileDescriptor.write("# Number of times to retry a test case causing a crash\n")
        else:
            fileDescriptor.write(self._getComments("failure_threshold"))
        fileDescriptor.write("failureThreshold {0}\n".format(self.failureThreshold))
        
        # Failure Timeout
        if defaultComments:
            fileDescriptor.write("# How long to wait between retrying test cases causing a crash\n")
        else:
            fileDescriptor.write(self._getComments("failureTimeout"))
        fileDescriptor.write("failureTimeout {0}\n".format(self.failureTimeout))
        
        # Receive Timeout
        if defaultComments:
            fileDescriptor.write("# How long for recv() to block when waiting on data from server\n")
        else:
            fileDescriptor.write(self._getComments("receiveTimeout"))
        fileDescriptor.write("receiveTimeout {0}\n".format(self.receiveTimeout))
        
        # Should Perform Test Run
        if defaultComments:
            fileDescriptor.write("# Whether to perform an unfuzzed test run before fuzzing\n")
        else:
            fileDescriptor.write(self._getComments("shouldPerformTestRun"))
        sPTR = 1 if self.shouldPerformTestRun else 0
        fileDescriptor.write("shouldPerformTestRun {0}\n".format(sPTR))
        
        # Protocol
        if defaultComments:
            fileDescriptor.write("# Protocol (udp or tcp)\n")
        else:
            fileDescriptor.write(self._getComments("proto"))
        fileDescriptor.write("proto {0}\n".format(self.proto))
        
        # Port
        if defaultComments:
            fileDescriptor.write("# Port number to connect to\n")
        else:
            fileDescriptor.write(self._getComments("port"))
        fileDescriptor.write("port {0}\n".format(self.port))
        
        # Source Port
        if defaultComments:
            fileDescriptor.write("# Port number to connect from\n")
        else:
            fileDescriptor.write(self._getComments("sourcePort"))
        fileDescriptor.write("sourcePort {0}\n".format(self.sourcePort))

        # Source IP
        if defaultComments:
            fileDescriptor.write("# Source IP to connect from\n")
        else:
            fileDescriptor.write(self._getComments("sourceIP"))
        fileDescriptor.write("sourceIP {0}\n\n".format(self.sourceIP))

        # Messages
        if finalMessageNum == -1:
            finalMessageNum = len(self.messageCollection.messages)-1
        if defaultComments:
            fileDescriptor.write("# The actual messages in the conversation\n# Each contains a message to be sent to or from the server, printably-formatted\n")
        for i in range(0, finalMessageNum+1):
            message = self.messageCollection.messages[i]
            if not defaultComments:
                fileDescriptor.write(self._getComments("message{0}".format(i)))
            fileDescriptor.write(message.getSerialized())
            
        
        if not defaultComments:
            fileDescriptor.write(self._getComments("endcomments"))
