#!/usr/bin/env python3
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
import scapy.all
from copy import deepcopy
from backend.proc_director import ProcDirector
from backend.fuzzer_types import Message, MessageCollection, Logger
from backend.packets import PROTO,IP
from mutiny_classes.mutiny_exceptions import *
from mutiny_classes.message_processor import MessageProcessorExtraParams, MessageProcessor
from mutiny_classes.exception_processor import ExceptionProcessor
from backend.fuzzer_data import FuzzerData
from backend.menu_functions import prompt, promptInt, promptString, validateNumberRange
from backend.fuzz_file_prep import prep


# Path to Radamsa binary
RADAMSA=os.path.abspath( os.path.join(__file__, "../radamsa/bin/radamsa") )
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

FUZZER_DATA = None
MONITOR = None

# colors TODO: add colors to error/warning messages
SUCCESS = "\033[92m"
WARNING = "\033[93m"
ERROR = "\033[91m"
CLEAR = "\033[00m"


def sendPacket(connection: socket, addr: tuple, outPacketData: bytearray):
    '''
    Takes a socket and outbound data packet (byteArray), sends it out.
    If debug mode is enabled, we print out the raw bytes
    '''
    connection.settimeout(FUZZER_DATA.receiveTimeout)
    if connection.type == socket.SOCK_STREAM:
        connection.send(outPacketData)
    else:
        connection.sendto(outPacketData,addr)

    print("\tSent %d byte packet" % (len(outPacketData)))
    if DEBUG_MODE:
        print("\tSent: %s" % (outPacketData))
        print("\tRaw Bytes: %s" % (Message.serializeByteArray(outPacketData)))


def receivePacket(connection: socket, addr: tuple, bytesToRead: int):
    readBufSize = 4096
    connection.settimeout(FUZZER_DATA.receiveTimeout)

    if connection.type == socket.SOCK_STREAM or connection.type == socket.SOCK_DGRAM or connection.type == socket.SOCK_RAW:
        response = bytearray(connection.recv(readBufSize))
    else:
        response, addr = bytearray(connection.recvfrom(readBufSize))
    
    
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

def get_addr(host):
    '''
    using the host parameter and protocol type, determines which format of address to use
    and calls message_processor.preConnect if proto is not L2raw
    '''
    socket_family = None
    if FUZZER_DATA.proto == 'L2raw':
        addr = (host,0)
        socket_family = socket.AF_PACKET
    else:
        addrs = socket.getaddrinfo(host,FUZZER_DATA.port)
        host = addrs[0][4][0]
        if host == "::1":
            host = "127.0.0.1"
        
        # cheap testing for ipv6/ipv4/unix
        # don't think it's worth using regex for this, since the user
        # will have to actively go out of their way to subvert this.
        if "." in host:
            socket_family = socket.AF_INET
            addr = (host,FUZZER_DATA.port)
        elif ":" in host:
            socket_family = socket.AF_INET6 
            addr = (host,FUZZER_DATA.port)
        else:
            socket_family = socket.AF_UNIX
            addr = (host)
        #just in case filename is like "./asdf" !=> af_inet
        if "/" in host:
            socket_family = socket.AF_UNIX
            addr = (host)

    return host, addr, socket_family

def bind_to_interface(connection, addr=None):
    if FUZZER_DATA.proto == 'L2raw':
        connection.bind(addr)
    else:
        if FUZZER_DATA.sourcePort != -1:
            # Only support right now for tcp or udp, but bind source port address to something
            # specific if requested
            if FUZZER_DATA.sourceIP != "" or FUZZER_DATA.sourceIP != "0.0.0.0":
                connection.bind((FUZZER_DATA.sourceIP, FUZZER_DATA.sourcePort))
            else:
                # User only specified a port, not an IP
                connection.bind(('0.0.0.0', FUZZER_DATA.sourcePort))
        elif FUZZER_DATA.sourceIP != "" and FUZZER_DATA.sourceIP != "0.0.0.0":
            # No port was specified, so 0 should auto-select
            connection.bind((FUZZER_DATA.sourceIP, 0))


def connect_to_tcp_socket(host, seed):
    host, addr, socket_family = get_addr(host)
    connection = socket.socket(socket_family, socket.SOCK_STREAM)
    bind_to_interface(connection)
    connection.connect(addr)
    return connection, addr

def connect_to_udp_socket(host, seed):
    host, addr, socket_family = get_addr(host)
    connection = socket.socket(socket_family, socket.SOCK_DGRAM)
    connection = bind_to_interface(connection)
    return connection, addr

def connect_to_tls_socket(host, seed):
    host, addr, socket_family = get_addr(host)
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
    bind_to_interface(connection)
    connection.connect(addr)
    
    return connection, addr

def connect_to_raw_socket(host, seed):
    host, addr, socket_family = get_addr(host)
    connection = socket.socket(socket_family,socket.SOCK_RAW, 0x0300)
    bind_to_interface(addr, connection)
    return connection, addr


def create_connection(host, seed, message_processor):
    '''
    handles the creation of a network connection for the fuzzing session and returns the connection
    '''
    connection = None
    supported_protocols = ['tcp','udp','tls','L2raw']
    if FUZZER_DATA.proto not in supported_protocols:
        # TODO: after moving print_error to ./util/, call it here
        print("[ERROR] The protocol specified in the .fuzzer file is not currently supported.\nIf you'd like, you can submit an issue or a PR for support!")
        sys.exit(0)

    # Call messageprocessor preconnect callback if it exists
    try:
        message_processor.preConnect(seed, host, FUZZER_DATA.port) 
    except AttributeError:
        pass

    if FUZZER_DATA.proto == 'tcp':
        connection, addr = connect_to_tcp_socket(host, seed)
    elif FUZZER_DATA.proto == 'udp':
        connection, addr = connect_to_udp_socket(host, seed)
    elif FUZZER_DATA.proto == 'tls':
        connection, addr = connect_to_tls_socket(host, seed)
    # must be a raw socket since we already checked if protocol was supported
    else :
        connection, addr = connect_to_raw_socket(host, seed)

    return connection, addr

def fuzz_subcomponents(message, seed):
    '''
    iterates through each subcomponent in a message and uses radamsa to generate fuzzed
    versions of each subcomponent if its .isFuzzed is set to True
    '''
    for subcomponent in message.subcomponents:
        if subcomponent.isFuzzed:
            radamsa = subprocess.Popen([RADAMSA, "--seed", str(seed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            byteArray = subcomponent.getAlteredByteArray()
            (fuzzedByteArray, error_output) = radamsa.communicate(input=byteArray)
            fuzzedByteArray = bytearray(fuzzedByteArray)
            subcomponent.setAlteredByteArray(fuzzedByteArray)

def send_fuzz_session_message(message, message_processor, seed, dump_raw):
    # Primarily used for deciding how to handle preFuzz/preSend callbacks
    message_has_subcomponents = len(message.subcomponents) > 1

    # Get original subcomponents for outbound callback only once
    original_subcomponents = [subcomponent.getOriginalByteArray() for subcomponent in message.subcomponents]
    
    if message_has_subcomponents:
        # For message with subcomponents, call prefuzz on fuzzed subcomponents
        for j in range(0, len(message.subcomponents)):
            subcomponent = message.subcomponents[j] 
            # Note: we WANT to fetch subcomponents every time on purpose
            # This way, if user alters subcomponent[0], it's reflected when
            # we call the function for subcomponent[1], etc
            actualSubcomponents = [subcomponent.getAlteredByteArray() for subcomponent in message.subcomponents]
            prefuzz = message_processor.preFuzzSubcomponentProcess(subcomponent.getAlteredByteArray(), MessageProcessorExtraParams(i, j, subcomponent.isFuzzed, original_subcomponents, actualSubcomponents))
            subcomponent.setAlteredByteArray(prefuzz)
    else:
        # If no subcomponents, call prefuzz on ENTIRE message
        actualSubcomponents = [subcomponent.getAlteredByteArray() for subcomponent in message.subcomponents]
        prefuzz = message_processor.preFuzzProcess(actualSubcomponents[0], MessageProcessorExtraParams(i, -1, message.isFuzzed, original_subcomponents, actualSubcomponents))
        message.subcomponents[0].setAlteredByteArray(prefuzz)

    # Skip fuzzing for seed == -1
    if seed > -1:
        # Now run the fuzzer for each fuzzed subcomponent
        fuzz_subcomponents(message, seed)
    
    # Fuzzing has now been done if this message is fuzzed
    # Always call preSend() regardless for subcomponents if there are any
    if message_has_subcomponents:
        for j in range(0, len(message.subcomponents)):
            subcomponent = message.subcomponents[j] 
            # See preFuzz above - we ALWAYS regather this to catch any updates between
            # callbacks from the user
            actualSubcomponents = [subcomponent.getAlteredByteArray() for subcomponent in message.subcomponents]
            presend = message_processor.preSendSubcomponentProcess(subcomponent.getAlteredByteArray(), MessageProcessorExtraParams(i, j, subcomponent.isFuzzed, original_subcomponents, actualSubcomponents))
            subcomponent.setAlteredByteArray(presend)
    # Always let the user make any final modifications pre-send, fuzzed or not
    actualSubcomponents = [subcomponent.getAlteredByteArray() for subcomponent in message.subcomponents]
    byteArrayToSend = message_processor.preSendProcess(message.getAlteredMessage(), MessageProcessorExtraParams(i, -1, message.isFuzzed, original_subcomponents, actualSubcomponents))

    if dump_raw:
        loc = os.path.join(DUMPDIR,"%d-outbound-seed-%d"%(i,dump_raw))
        if message.isFuzzed:
            loc+="-fuzzed"
        with open(loc,"wb") as f:
            f.write(repr(str(byteArrayToSend))[1:-1])

    sendPacket(connection, addr, byteArrayToSend)

def receive_fuzz_session_message(message, connection, addr, logger, message_processor, dump_raw):
    # Receiving packet from server
    messageByteArray = message.getAlteredMessage()
    data = receivePacket(connection,addr,len(messageByteArray))
    if data == messageByteArray:
        print("\tReceived expected response")
    if logger != None:
        logger.setReceivedMessageData(i, data)

    message_processor.postReceiveProcess(data, MessageProcessorExtraParams(i, -1, False, [messageByteArray], [data]))
    if dumpraw:
        loc = os.path.join(DUMPDIR,"%d-inbound-seed-%d"%(i,dumpraw))
        with open(loc,"wb") as f:
            f.write(repr(str(data))[1:-1])


def performRun(host: str, logger: Logger, message_processor: MessageProcessor, dump_raw, seed: int = -1):
    '''
    Perform a fuzz run.  
    If seed is -1, don't perform fuzzing (test run)
    '''
    # Before doing anything, set up logger
    # Otherwise, if connection is refused, we'll log last, but it will be wrong
    if logger != None:
        logger.resetForNewRun()
    
    connection, addr = create_connection(host, seed, message_processor)

    i = 0   
    for i in range(0, len(FUZZER_DATA.messageCollection.messages)):
        message = FUZZER_DATA.messageCollection.messages[i]
        
        # Go ahead and revert any fuzzing or messageprocessor changes before proceeding
        message.resetAlteredMessage()

        if message.isOutbound():
            send_fuzz_session_message(message, message_processor, seed, dump_raw)
        else: 
            receive_fuzz_session_message(message, connection, addr, logger, message_processor, dump_raw)

        if logger != None:  
            logger.setHighestMessageNumber(i)
        i += 1

    connection.close()

#----------------------------------------------------
# Set MIN_RUN_NUMBER and MAX_RUN_NUMBER when provided
# by the user below
def getRunNumbersFromArgs(strArgs: str):
    if "-" in strArgs:
        testNumbers = strArgs.split("-")
        if len(testNumbers) == 2:
            if len(testNumbers[1]): #e.g. strArgs="1-50"
                # cant have min > max
                if (int(testNumbers[0]) > int(testNumbers[1])):
                    sys.exit("Invalid test range given: %s" % strArgs)
                return (int(testNumbers[0]), int(testNumbers[1]))
            else:                   #e.g. strArgs="3-" (equiv. of --skip-to)
                return (int(testNumbers[0]),-1)
        else: #e.g. strArgs="1-2-3-5.." 
            sys.exit("Invalid test range given: %s" % strArgs)
    else:
        # If they pass a non-int, allow this to bomb out
        return (int(strArgs),int(strArgs)) 

#----------------------------------------------------
# Set up signal handler for CTRL+C
def sigint_handler(signal: int, frame: object):
    # Quit on ctrl-c
    print("\nSIGINT received, stopping\n")
    sys.exit(0)

def raise_next_monitor_event_if_any(is_paused):
    # Check the monitor queue for exceptions generated during run
    if not MONITOR.queue.empty():
        print('Monitor event detected')
        exception = MONITOR.queue.get()
        
        if is_paused:
            if isinstance(exception, PauseFuzzingException):
                # Duplicate pauses are fine, a no-op though
                pass
            elif not isinstance(exception, ResumeFuzzingException):
                # Any other exception besides resume after pause makes no sense
                print(f'Received exception while Mutiny was paused, can\'t handle properly:')
                print(repr(exception))
                print('Exception will be ignored and discarded.')
                return
        raise exception

def fuzz(args: argparse.Namespace, testing: bool = False):
    # initialize fuzzing environment according to user provided arguments
    (messageProcessor, exceptionProcessor, logger) = fuzzSetup(args, testing)

    i = MIN_RUN_NUMBER-1 if FUZZER_DATA.shouldPerformTestRun else MIN_RUN_NUMBER
    failureCount = 0
    loop_len = len(SEED_LOOP) # if --loop
    host = args.target_host
    isReproduce = args.quiet
    logAll = args.logAll if not isReproduce else False
    is_paused = False

    while True:
        lastMessageCollection = deepcopy(FUZZER_DATA.messageCollection)
        wasCrashDetected = False
        if not is_paused and args.sleeptime > 0.0:
            print("\n** Sleeping for %.3f seconds **" % args.sleeptime)
            time.sleep(args.sleeptime)

        try:
            # Check for any exceptions from Monitor
            # Intentionally do this before and after a run in case we have back-to-back exceptions
            # (Example: Crash, then Pause, then Resume
            raise_next_monitor_event_if_any(is_paused)
            
            if is_paused:
                # Busy wait, might want to do something more clever with Condition or Event later
                time.sleep(0.5)
                continue
            
            try:
                
                if args.dumpraw:
                    print("\n\nPerforming single raw dump case: %d" % args.dumpraw)
                    performRun(host, logger, messageProcessor, args.dumpraw,seed=args.dumpraw,)  
                elif i == MIN_RUN_NUMBER-1:
                    print("\n\nPerforming test run without fuzzing...")
                    performRun(host, logger, messageProcessor, args.dumpraw, seed=-1 ) 
                elif loop_len: 
                    print("\n\nFuzzing with seed %d" % (SEED_LOOP[i%loop_len]))
                    performRun(host, logger, messageProcessor, args.dumpraw, seed=SEED_LOOP[i%loop_len]) 
                else:
                    print("\n\nFuzzing with seed %d" % (i))
                    performRun(host, logger, messageProcessor, args.dumpraw, seed=i) 
                #if --quiet, (logger==None) => AttributeError
                if logAll:
                    try:
                        logger.outputLog(i, FUZZER_DATA.messageCollection, "LogAll ")
                    except AttributeError:
                        pass 
            except Exception as e:
                if logAll:
                    try:
                        logger.outputLog(i, FUZZER_DATA.messageCollection, "LogAll ")
                    except AttributeError:
                        pass
                
                if e.__class__ in MessageProcessorExceptions.all:
                    # If it's a MessageProcessorException, assume the MP raised it during the run
                    # Otherwise, let the MP know about the exception
                    raise e
                else:
                    exceptionProcessor.processException(e)
                    # Will not get here if processException raises another exception
                    print("Exception ignored: %s" % (repr(e)))
            
            # Check for any exceptions from Monitor
            # Intentionally do this before and after a run in case we have back-to-back exceptions
            # (Example: Crash, then Pause, then Resume
            raise_next_monitor_event_if_any(is_paused)
        except PauseFuzzingException as e:
            print('Mutiny received a pause exception, pausing until monitor sends a resume...')
            is_paused = True

        except ResumeFuzzingException as e:
            if is_paused:
                print('Mutiny received a resume exception, continuing to run.')
                is_paused = False
            else:
                print('Mutiny received a resume exception but wasn\'t paused, ignoring and continuing.')

        except LogCrashException as e:
            if failureCount == 0:
                try:
                    print("Mutiny detected a crash")
                    logger.outputLog(i, FUZZER_DATA.messageCollection, str(e))
                except AttributeError:  
                    pass   

            if logAll:
                try:
                    logger.outputLog(i, FUZZER_DATA.messageCollection, "LogAll ")
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
                logger.outputLog(i, FUZZER_DATA.messageCollection, str(e))
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
            if failureCount < FUZZER_DATA.failureThreshold:
                print("Failure %d of %d allowed for seed %d" % (failureCount, FUZZER_DATA.failureThreshold, i))
                print("The test run didn't complete, continuing after %d seconds..." % (FUZZER_DATA.failureTimeout))
                time.sleep(FUZZER_DATA.failureTimeout)
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

def fuzzSetup(args: argparse.Namespace, testing=False):
    global FUZZER_DATA, MIN_RUN_NUMBER, MAX_RUN_NUMBER, SEED_LOOP

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


    outputDataFolderPath = os.path.join("%s_%s" % (os.path.splitext(fuzzerFilePath)[0], "logs"), datetime.datetime.now().strftime("%Y-%m-%d,%H%M%S"))
    fuzzerFolder = os.path.abspath(os.path.dirname(fuzzerFilePath))

    FUZZER_DATA = FuzzerData()
    print("Reading in fuzzer data from %s..." % (fuzzerFilePath))
    FUZZER_DATA.readFromFile(fuzzerFilePath)

    (messageProcessor, exceptionProcessor, logger) = processorSetup( fuzzerFolder, outputDataFolderPath, args)

    if not testing:
        signal.signal(signal.SIGINT, sigint_handler)

    return (messageProcessor,  exceptionProcessor, logger)

    
    
def processorSetup( fuzzerFolder: str, outputDataFolderPath: str, args: argparse.Namespace):
    ######## Processor Setup ################
    # The processor just acts as a container #
    # class that will import custom versions #
    # messageProcessor/exceptionProessor/    #
    # monitor, if they are found in the      #
    # process_dir specified in the .fuzzer   #
    # file generated by fuzz_prep.py         #
    ##########################################
    global MONITOR, DUMPDIR

    # Assign options to variables, error on anything that's missing/invalid
    processorDirectory = FUZZER_DATA.processorDirectory
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
        ### monitor.queue = enqueued exceptions
    MONITOR = procDirector.startMonitor(args.target_host,FUZZER_DATA.port)

    #! make it so logging message does not appear if reproducing (i.e. -r x-y cmdline arg is set)
    logger = None 

    if not args.quiet:
        print("Logging to %s" % (outputDataFolderPath))
        logger = Logger(outputDataFolderPath)

    if args.dumpraw:
        if not args.quiet:
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

    return (messageProcessor, exceptionProcessor, logger)

def parseFuzzArgs(parser):
    '''
    parse arguments for fuzzing
    '''
    parser.add_argument("prepped_fuzz", help="Path to file.fuzzer")
    parser.add_argument("target_host", help="Target to fuzz - hostname/ip address (typical) or outbound interface name (L2raw only)")
    parser.add_argument("-s", "--sleeptime", help="Time to sleep between fuzz cases (float)", type=float, default=0)

    seed_constraint = parser.add_mutually_exclusive_group()
    seed_constraint.add_argument("-r", "--range", help="Run only the specified cases. Acceptable arg formats: [ X | X- | X-Y ], for integers X,Y") 
    seed_constraint.add_argument("-l", "--loop", help="Loop/repeat the given finite number range. Acceptible arg format: [ X | X-Y | X,Y,Z-Q,R | ...]")
    seed_constraint.add_argument("-d", "--dumpraw", help="Test single seed, dump to 'dumpraw' folder", type=int)

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", help="Don't log the outputs", action="store_true")
    verbosity.add_argument("--logAll", help="Log all the outputs", action="store_true")
    parser.set_defaults(func=fuzz)

def parsePrepArgs(parser):
    '''
    parse arguments for fuzzer file preparation
    '''
    parser.add_argument("pcap_file", help="Pcap/c_array output from wireshark")
    parser.add_argument("-d","--processor_dir", help = "Location of custom pcap Message/exception/log/monitor processors if any, see appropriate *processor.py source in ./mutiny_classes/ for implementation details", nargs=1, default=["default"])
    parser.add_argument("-a", "--dump_ascii", help="Dump the ascii output from packets ", action="store_true", default=False)
    parser.add_argument("-f", "--force", help="Take all default options", action = "store_true", default=False) 
    parser.add_argument("-r", "--raw", help="Pull all layer 2+ data / create .fuzzer for raw sockets", action = "store_true", default=False) 
    parser.set_defaults(func=prep)
    
def parseArguments():
    #TODO: add description/license/ascii art print out??
    # FIXME: let fuzz run by default and prep indiciate a subcommand
    desc =  "======== The Mutiny Fuzzing Framework ==========" 
    epi = "==" * 24 + '\n'
    parser = argparse.ArgumentParser(description=desc,epilog=epi)

    subparsers = parser.add_subparsers(title='subcommands')
    prepParser = subparsers.add_parser('prep', help='convert a pcap/c_array output into a .fuzzer file') 
    fuzzParser = subparsers.add_parser('fuzz', help='begin fuzzing using a .fuzzer file')

    parsePrepArgs(prepParser)
    parseFuzzArgs(fuzzParser)

    return parser.parse_args()

if __name__ == '__main__':
    # Usage case
    if len(sys.argv) < 3:
        sys.argv.append('-h')

    args = parseArguments()

    args.func(args)

        
