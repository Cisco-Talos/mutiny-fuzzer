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
# This is the main fuzzing script.  It takes a .fuzzer file and performs the
# actual fuzzing
#
#------------------------------------------------------------------

import datetime
import errno
import importlib
import os.path
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import argparse
import ssl
from copy import deepcopy
from backend.proc_director import ProcDirector
from backend.fuzzer_types import Message, MessageCollection, Logger
from backend.packets import PROTO,IP
from mutiny_classes.mutiny_exceptions import *
from mutiny_classes.message_processor import MessageProcessorExtraParams
from backend.fuzzerdata import FuzzerData
from backend.menu_functions import validateNumberRange

# Path to Radamsa binary
RADAMSA=os.path.abspath( os.path.join(__file__, "../radamsa-0.6/bin/radamsa") )
# Whether to print debug info
DEBUG_MODE=False
# Test number to start from, 0 default
MIN_RUN_NUMBER=0
# Test number to go to, -1 is unlimited
MAX_RUN_NUMBER=-1
# For seed loop, finite range to repeat   
SEED_LOOP = []
# For dumpraw option, dump into log directory by default, else 'dumpraw'
DUMPDIR = ""

# Takes a socket and outbound data packet (byteArray), sends it out.
# If debug mode is enabled, we print out the raw bytes
def sendPacket(connection, addr, outPacketData):
    connection.settimeout(fuzzerData.receiveTimeout)
    if connection.type == socket.SOCK_STREAM:
        connection.send(outPacketData)
    else:
        connection.sendto(outPacketData,addr)

    print("\tSent %d byte packet" % (len(outPacketData)))
    if DEBUG_MODE:
        print("\tSent: %s" % (outPacketData))
        print("\tRaw Bytes: %s" % (Message.serializeByteArray(outPacketData)))


def receivePacket(connection, addr, bytesToRead):
    readBufSize = 4096
    connection.settimeout(fuzzerData.receiveTimeout)

    if connection.type == socket.SOCK_STREAM or connection.type == socket.SOCK_DGRAM:
        response = bytearray(connection.recv(readBufSize))
    else:
        response = bytearray(connection.recvfrom(readBufSize,addr))
    
    
    if len(response) == 0:
        # If 0 bytes are recv'd, the server has closed the connection
        # per python documentation
        raise ConnectionClosedException("Server has closed the connection")
    if bytesToRead > readBufSize:
        # If we're trying to read > 4096, don't actually bother trying to guarantee we'll read 4096
        # Just keep reading in 4096 chunks until we should have read enough, and then return
        # whether or not it's as much data as expected
        i = readBufSize
        while i < bytesToRead:
            response += bytearray(connection.recv(readBufSize))
            i += readBufSize
            
    print("\tReceived %d bytes" % (len(response)))
    if DEBUG_MODE:
        print("\tReceived: %s" % (response))
    return response

# Perform a fuzz run.  
# If seed is -1, don't perform fuzzing (test run)
def performRun(fuzzerData, host, logger, messageProcessor, seed=-1):
    # Before doing anything, set up logger
    # Otherwise, if connection is refused, we'll log last, but it will be wrong
    if logger != None:
        logger.resetForNewRun()
    
    addrs = socket.getaddrinfo(host,fuzzerData.port)
    host = addrs[0][4][0]
    if host == "::1":
        host = "127.0.0.1"
    
    # cheap testing for ipv6/ipv4/unix
    # don't think it's worth using regex for this, since the user
    # will have to actively go out of their way to subvert this.
    if "." in host:
        socket_family = socket.AF_INET
        addr = (host,fuzzerData.port)
    elif ":" in host:
        socket_family = socket.AF_INET6 
        addr = (host,fuzzerData.port)
    else:
        socket_family = socket.AF_UNIX
        addr = (host)

    #just in case filename is like "./asdf" !=> AF_INET
    if "/" in host:
        socket_family = socket.AF_UNIX
        addr = (host)
    
    # Call messageprocessor preconnect callback if it exists
    try:
        messageProcessor.preConnect(seed, host, fuzzerData.port) 
    except AttributeError:
        pass
    
    # for TCP/UDP/RAW support
    if fuzzerData.proto == "tcp":
        connection = socket.socket(socket_family,socket.SOCK_STREAM)
        # Don't connect yet, until after we do any binding below
    elif fuzzerData.proto == "tls":
        try:
            _create_unverified_https_context = ssl._create_unverified_context
        except AttributeError:
            # Legacy Python that doesn't verify HTTPS certificates by default
            pass
        else:
            # Handle target environment that doesn't support HTTPS verification
            ssl._create_default_https_context = _create_unverified_https_context
        tcpConnection = socket.socket(socket_family,socket.SOCK_STREAM)
        connection = ssl.wrap_socket(tcpConnection)
        # Don't connect yet, until after we do any binding below
    elif fuzzerData.proto == "udp":
        connection = socket.socket(socket_family,socket.SOCK_DGRAM)
    # PROTO = dictionary of assorted L3 proto => proto number
    # e.g. "icmp" => 1
    elif fuzzerData.proto in PROTO:
        connection = socket.socket(socket_family,socket.SOCK_RAW,PROTO[fuzzerData.proto]) 
        if fuzzerData.proto != "raw":
            connection.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,0)
        addr = (host,0)
        try:
            connection = socket.socket(socket_family,socket.SOCK_RAW,PROTO[fuzzerData.proto]) 
        except Exception as e:
            print(e)
            print("Unable to create raw socket, please verify that you have sudo access")
            sys.exit(0)
    elif fuzzerData.proto == "L2raw":
        connection = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,0x0300)
    else:
        addr = (host,0)
        try:
            #test if it's a valid number 
            connection = socket.socket(socket_family,socket.SOCK_RAW,int(fuzzerData.proto)) 
            connection.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,0)
        except Exception as e:
            print(e)
            print("Unable to create raw socket, please verify that you have sudo access")
            sys.exit(0)
        
    if fuzzerData.proto == "tcp" or fuzzerData.proto == "udp" or fuzzerData.proto == "tls":
        # Specifying source port or address is only supported for tcp and udp currently
        if fuzzerData.sourcePort != -1:
            # Only support right now for tcp or udp, but bind source port address to something
            # specific if requested
            if fuzzerData.sourceIP != "" or fuzzerData.sourceIP != "0.0.0.0":
                connection.bind((fuzzerData.sourceIP, fuzzerData.sourcePort))
            else:
                # User only specified a port, not an IP
                connection.bind(('0.0.0.0', fuzzerData.sourcePort))
        elif fuzzerData.sourceIP != "" and fuzzerData.sourceIP != "0.0.0.0":
            # No port was specified, so 0 should auto-select
            connection.bind((fuzzerData.sourceIP, 0))
    if fuzzerData.proto == "tcp" or fuzzerData.proto == "tls":
        # Now that we've had a chance to bind as necessary, connect
        connection.connect(addr)

    i = 0   
    for i in range(0, len(fuzzerData.messageCollection.messages)):
        message = fuzzerData.messageCollection.messages[i]
        
        # Go ahead and revert any fuzzing or messageprocessor changes before proceeding
        message.resetAlteredMessage()

        if message.isOutbound():
            # Primarily used for deciding how to handle preFuzz/preSend callbacks
            doesMessageHaveSubcomponents = len(message.subcomponents) > 1

            # Get original subcomponents for outbound callback only once
            originalSubcomponents = [subcomponent.getOriginalByteArray() for subcomponent in message.subcomponents]
            
            if doesMessageHaveSubcomponents:
                # For message with subcomponents, call prefuzz on fuzzed subcomponents
                for j in range(0, len(message.subcomponents)):
                    subcomponent = message.subcomponents[j] 
                    # Note: we WANT to fetch subcomponents every time on purpose
                    # This way, if user alters subcomponent[0], it's reflected when
                    # we call the function for subcomponent[1], etc
                    actualSubcomponents = [subcomponent.getAlteredByteArray() for subcomponent in message.subcomponents]
                    prefuzz = messageProcessor.preFuzzSubcomponentProcess(subcomponent.getAlteredByteArray(), MessageProcessorExtraParams(i, j, subcomponent.isFuzzed, originalSubcomponents, actualSubcomponents))
                    subcomponent.setAlteredByteArray(prefuzz)
            else:
                # If no subcomponents, call prefuzz on ENTIRE message
                actualSubcomponents = [subcomponent.getAlteredByteArray() for subcomponent in message.subcomponents]
                prefuzz = messageProcessor.preFuzzProcess(actualSubcomponents[0], MessageProcessorExtraParams(i, -1, message.isFuzzed, originalSubcomponents, actualSubcomponents))
                message.subcomponents[0].setAlteredByteArray(prefuzz)

            # Skip fuzzing for seed == -1
            if seed > -1:
                # Now run the fuzzer for each fuzzed subcomponent
                for subcomponent in message.subcomponents:
                    if subcomponent.isFuzzed:
                        radamsa = subprocess.Popen([RADAMSA, "--seed", str(seed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        byteArray = subcomponent.getAlteredByteArray()
                        (fuzzedByteArray, error_output) = radamsa.communicate(input=byteArray)
                        fuzzedByteArray = bytearray(fuzzedByteArray)
                        subcomponent.setAlteredByteArray(fuzzedByteArray)
            
            # Fuzzing has now been done if this message is fuzzed
            # Always call preSend() regardless for subcomponents if there are any
            if doesMessageHaveSubcomponents:
                for j in range(0, len(message.subcomponents)):
                    subcomponent = message.subcomponents[j] 
                    # See preFuzz above - we ALWAYS regather this to catch any updates between
                    # callbacks from the user
                    actualSubcomponents = [subcomponent.getAlteredByteArray() for subcomponent in message.subcomponents]
                    presend = messageProcessor.preSendSubcomponentProcess(subcomponent.getAlteredByteArray(), MessageProcessorExtraParams(i, j, subcomponent.isFuzzed, originalSubcomponents, actualSubcomponents))
                    subcomponent.setAlteredByteArray(presend)
            
            # Always let the user make any final modifications pre-send, fuzzed or not
            actualSubcomponents = [subcomponent.getAlteredByteArray() for subcomponent in message.subcomponents]
            byteArrayToSend = messageProcessor.preSendProcess(message.getAlteredMessage(), MessageProcessorExtraParams(i, -1, message.isFuzzed, originalSubcomponents, actualSubcomponents))

            if args.dumpraw:
                loc = os.path.join(DUMPDIR,"%d-outbound-seed-%d"%(i,args.dumpraw))
                if message.isFuzzed:
                    loc+="-fuzzed"
                with open(loc,"wb") as f:
                    f.write(repr(str(byteArrayToSend))[1:-1])

            sendPacket(connection, addr, byteArrayToSend)
        else: 
            # Receiving packet from server
            messageByteArray = message.getAlteredMessage()
            data = receivePacket(connection,addr,len(messageByteArray))
            if data == messageByteArray:
                print("\tReceived expected response")
            if logger != None:
                logger.setReceivedMessageData(i, data)
        
            messageProcessor.postReceiveProcess(data, MessageProcessorExtraParams(i, -1, False, [messageByteArray], [data]))

            if args.dumpraw:
                loc = os.path.join(DUMPDIR,"%d-inbound-seed-%d"%(i,args.dumpraw))
                with open(loc,"wb") as f:
                    f.write(repr(str(data))[1:-1])

        if logger != None:  
            logger.setHighestMessageNumber(i)
        

        i += 1
    
    connection.close()

# Usage case
if len(sys.argv) < 3:
    sys.argv.append('-h')

#TODO: add description/license/ascii art print out??
desc =  "======== The Mutiny Fuzzing Framework ==========" 
epi = "==" * 24 + '\n'

parser = argparse.ArgumentParser(description=desc,epilog=epi)
parser.add_argument("prepped_fuzz", help="Path to file.fuzzer")
parser.add_argument("target_host", help="Target to fuzz")
parser.add_argument("-s","--sleeptime",help="Time to sleep between fuzz cases (float)",type=float,default=0)
seed_constraint = parser.add_mutually_exclusive_group()
seed_constraint.add_argument("-r", "--range", help="Run only the specified cases. Acceptable arg formats: [ X | X- | X-Y ], for integers X,Y") 
seed_constraint.add_argument("-l", "--loop", help="Loop/repeat the given finite number range. Acceptible arg format: [ X | X-Y | X,Y,Z-Q,R | ...]")
seed_constraint.add_argument("-d", "--dumpraw", help="Test single seed, dump to 'dumpraw' folder",type=int)

verbosity = parser.add_mutually_exclusive_group()
verbosity.add_argument("-q", "--quiet", help="Don't log the outputs",action="store_true")
verbosity.add_argument("--logAll", help="Log all the outputs",action="store_true")

args = parser.parse_args()

#----------------------------------------------------
# Set MIN_RUN_NUMBER and MAX_RUN_NUMBER when provided
# by the user below
def getRunNumbersFromArgs(strArgs):
    if "-" in strArgs:
        testNumbers = strArgs.split("-")
        if len(testNumbers) == 2:
            if len(testNumbers[1]): #e.g. strArgs="1-50"
                return (int(testNumbers[0]), int(testNumbers[1]))
            else:                   #e.g. strArgs="3-" (equiv. of --skip-to)
                return (int(testNumbers[0]),-1)
        else: #e.g. strArgs="1-2-3-5.." 
            sys.exit("Invalid test range given: %s" % args)
    else:
        # If they pass a non-int, allow this to bomb out
        return (int(strArgs),int(strArgs)) 
#----------------------------------------------------

#Populate global arguments from parseargs
fuzzerFilePath = args.prepped_fuzz
host = args.target_host
#Assign Lower/Upper bounds on test cases as needed
if args.range:
    (MIN_RUN_NUMBER, MAX_RUN_NUMBER) = getRunNumbersFromArgs(args.range)
elif args.loop:
    SEED_LOOP = validateNumberRange(args.loop,True) 

#Check for dependency binaries
if not os.path.exists(RADAMSA):
    sys.exit("Could not find radamsa in %s... did you build it?" % RADAMSA)

#Logging options
isReproduce = False
logAll = False

if args.quiet:
    isReproduce = True
elif args.logAll:
    logAll = True


outputDataFolderPath = os.path.join("%s_%s" % (os.path.splitext(fuzzerFilePath)[0], "logs"), datetime.datetime.now().strftime("%Y-%m-%d,%H%M%S"))
fuzzerFolder = os.path.abspath(os.path.dirname(fuzzerFilePath))

########## Declare variables for scoping, "None"s will be assigned below
messageProcessor = None
monitor = None

###Here we read in the fuzzer file into a dictionary for easier variable propagation
optionDict = {"unfuzzedBytes":{}, "message":[]}

fuzzerData = FuzzerData()
print("Reading in fuzzer data from %s..." % (fuzzerFilePath))
fuzzerData.readFromFile(fuzzerFilePath)

######## Processor Setup ################
# The processor just acts as a container #
# class that will import custom versions #
# messageProcessor/exceptionProessor/    #
# monitor, if they are found in the      #
# process_dir specified in the .fuzzer   #
# file generated by fuzz_prep.py         #
##########################################

# Assign options to variables, error on anything that's missing/invalid
processorDirectory = fuzzerData.processorDirectory
if processorDirectory == "default":
    # Default to fuzzer file folder
    processorDirectory = fuzzerFolder
else:
    # Make sure fuzzer file path is prepended
    processorDirectory = os.path.join(fuzzerFolder, processorDirectory)

#Create class director, which import/overrides processors as appropriate
procDirector = ProcDirector(processorDirectory)

########## Launch child monitor thread
    ### monitor.task = spawned thread
    ### monitor.crashEvent = threading.Event()
monitor = procDirector.startMonitor(host,fuzzerData.port)

#! make it so logging message does not appear if reproducing (i.e. -r x-y cmdline arg is set)
logger = None 

if not isReproduce:
    print("Logging to %s" % (outputDataFolderPath))
    logger = Logger(outputDataFolderPath)

if args.dumpraw:
    if not isReproduce:
        DUMPDIR = outputDataFolderPath
    else:
        DUMPDIR = "dumpraw"
        try:
            os.mkdir("dumpraw")
        except:
            print("Unable to create dumpraw dir")
            pass
    

exceptionProcessor = procDirector.exceptionProcessor()
messageProcessor = procDirector.messageProcessor()

# Set up signal handler for CTRL+C and signals from child monitor thread
# since this is the same signal, we use the monitor.crashEvent flag()
# to differentiate between a CTRL+C and a interrupt_main() call from child 
def sigint_handler(signal, frame):
    if not monitor.crashEvent.isSet():
        # No event = quit
        # Quit on ctrl-c
        print("\nSIGINT received, stopping\n")
        sys.exit(0)

signal.signal(signal.SIGINT, sigint_handler)

########## Begin fuzzing
i = MIN_RUN_NUMBER-1 if fuzzerData.shouldPerformTestRun else MIN_RUN_NUMBER
failureCount = 0
loop_len = len(SEED_LOOP) # if --loop

while True:
    lastMessageCollection = deepcopy(fuzzerData.messageCollection)
    wasCrashDetected = False
    print("\n** Sleeping for %.3f seconds **" % args.sleeptime)
    time.sleep(args.sleeptime)
    
    try:
        try:
            if args.dumpraw:
                print("\n\nPerforming single raw dump case: %d" % args.dumpraw)
                performRun(fuzzerData, host, logger, messageProcessor, seed=args.dumpraw)  
            elif i == MIN_RUN_NUMBER-1:
                print("\n\nPerforming test run without fuzzing...")
                performRun(fuzzerData, host, logger, messageProcessor, seed=-1) 
            elif loop_len: 
                print("\n\nFuzzing with seed %d" % (SEED_LOOP[i%loop_len]))
                performRun(fuzzerData, host, logger, messageProcessor, seed=SEED_LOOP[i%loop_len]) 
            else:
                print("\n\nFuzzing with seed %d" % (i))
                performRun(fuzzerData, host, logger, messageProcessor, seed=i) 
            #if --quiet, (logger==None) => AttributeError
            if logAll:
                try:
                    logger.outputLog(i, fuzzerData.messageCollection, "LogAll ")
                except AttributeError:
                    pass
                 
        except Exception as e:
            if monitor.crashEvent.isSet():
                print("Crash event detected")
                try:
                    logger.outputLog(i, fuzzerData.messageCollection, "Crash event detected")
                    #exit()
                except AttributeError: 
                    pass
                monitor.crashEvent.clear()

            elif logAll:
                try:
                    logger.outputLog(i, fuzzerData.messageCollection, "LogAll ")
                except AttributeError:
                    pass
            
            if e.__class__ in MessageProcessorExceptions.all:
                # If it's a MessageProcessorException, assume the MP raised it during the run
                # Otherwise, let the MP know about the exception
                raise e
            else:
                exceptionProcessor.processException(e)
                # Will not get here if processException raises another exception
                print("Exception ignored: %s" % (str(e)))
        
    except LogCrashException as e:
        if failureCount == 0:
            try:
                print("MessageProcessor detected a crash")
                logger.outputLog(i, fuzzerData.messageCollection, str(e))
            except AttributeError:  
                pass   

        if logAll:
            try:
                logger.outputLog(i, fuzzerData.messageCollection, "LogAll ")
            except AttributeError:
                pass

        failureCount = failureCount + 1
        wasCrashDetected = True

    except AbortCurrentRunException as e:
        # Give up on the run early, but continue to the next test
        # This means the run didn't produce anything meaningful according to the processor
        print("Run aborted: %s" % (str(e)))
    
    except RetryCurrentRunException as e:
        # Same as AbortCurrentRun but retry the current test rather than skipping to next
        print("Retrying current run: %s" % (str(e)))
        # Slightly sketchy - a continue *should* just go to the top of the while without changing i
        continue
        
    except LogAndHaltException as e:
        if logger:
            logger.outputLog(i, fuzzerData.messageCollection, str(e))
            print("Received LogAndHaltException, logging and halting")
        else:
            print("Received LogAndHaltException, halting but not logging (quiet mode)")
        exit()
        
    except LogLastAndHaltException as e:
        if logger:
            if i > MIN_RUN_NUMBER:
                print("Received LogLastAndHaltException, logging last run and halting")
                if MIN_RUN_NUMBER == MAX_RUN_NUMBER:
                    #in case only 1 case is run
                    logger.outputLastLog(i, lastMessageCollection, str(e))
                    print("Logged case %d" % i)
                else:
                    logger.outputLastLog(i-1, lastMessageCollection, str(e))
            else:
                print("Received LogLastAndHaltException, skipping logging (due to last run being a test run) and halting")
        else:
            print("Received LogLastAndHaltException, halting but not logging (quiet mode)")
        exit()

    except HaltException as e:
        print("Received HaltException halting")
        exit()

    if wasCrashDetected:
        if failureCount < fuzzerData.failureThreshold:
            print("Failure %d of %d allowed for seed %d" % (failureCount, fuzzerData.failureThreshold, i))
            print("The test run didn't complete, continuing after %d seconds..." % (fuzzerData.failureTimeout))
            time.sleep(fuzzerData.failureTimeout)
        else:
            print("Failed %d times, moving to next test." % (failureCount))
            failureCount = 0
            i += 1
    else:
        i += 1
    
    # Stop if we have a maximum and have hit it
    if MAX_RUN_NUMBER >= 0 and i > MAX_RUN_NUMBER:
        exit()

    if args.dumpraw:
        exit()
        
