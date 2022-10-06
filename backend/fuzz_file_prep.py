#------------------------------------------------------------------
# Prep traffic log for fuzzing
#
# Cisco Confidential
# November 2014, created within ASIG
# Author James Spadaro (jaspadar)
# Contributor Lilith Wyatt (liwyatt)
#
# Copyright (c) 2014-2015 by Cisco Systems, Inc.
# All rights reserved.
#
# takes pcap or c_arrays output from Wireshark and 
# processes it into a .fuzzer file for use with mutiny.py
#------------------------------------------------------------------

import os
import sys
import argparse
from backend.fuzzer_types import Message
from backend.menu_functions import prompt, promptInt, promptString, validateNumberRange
from backend.fuzzer_data import FuzzerData
import scapy.all

SUCCESS = "\033[92m"
WARNING = "\033[93m"
ERROR = "\033[91m"
CLEAR = "\033[00m"

STATE_BETWEEN_MESSAGES= 0
STATE_READING_MESSAGES = 2
STATE_COMBINING_PACKETS = 3
LAST_MESSAGE_DIRECTION = -1
FORCE_DEFAULTS = False
INPUT_FILE_PATH = ""
DEFAULT_PORT = None
FUZZER_DATA = None



def prep(args: argparse.Namespace):
    '''
    facilitates
    1. processing of user specified pcap or C_array file
    2. user configuration of .fuzzer format
    3. creation of the .fuzzer file
    '''
    global  INPUT_FILE_PATH, FORCE_DEFAULTS, FUZZER_DATA
    INPUT_FILE_PATH = args.pcap_file
    FORCE_DEFAULTS = args.force

    FUZZER_DATA = FuzzerData()
    FUZZER_DATA.processorDirectory = args.processor_dir[0]

    processInputFile() # extract inputData from input file

    genFuzzConfig() # prompt user for .fuzzer configuration preferences

    writeFuzzerFile() # write .fuzzer file


def processInputFile():
    '''
    Processes input files by opening them and dispatching a pcap ingestor. if pcap ingestor fails,
    attempts to dispach a c_array ingestor
    '''

    if not os.path.isfile(INPUT_FILE_PATH):
        print(ERROR + "Cannot read input %s" % (INPUT_FILE_PATH) + CLEAR)
        exit()

    with open(INPUT_FILE_PATH, 'r') as inputFile:
        # This is a little naive, but it works
        # These two get recreated frequently
        message = Message()
        tempMessageData = ""

        state = STATE_BETWEEN_MESSAGES # Track what we're looking for
        
        # Allow combining packets in same direction back-to-back into one message
        askedToCombinePackets = False
        isCombiningPackets = False

        print("Processing %s..." % (INPUT_FILE_PATH))
    
        try:
            processPcap(inputFile) # Process as Pcap preferentially
        except Exception as rdpcap_e:
            print(ERROR + str(rdpcap_e) + CLEAR)
            print("Processing as c_array...")
            try:
                processCArray(inputFile)
            except Exception as e:
                print(ERROR + "Unable to parse as pcap: %s" % (str(rdpcap_e)))
                print("Unable to parse as c_arrays: %s" % (str(e)) + CLEAR)

    if len(FUZZER_DATA.messageCollection.messages) == 0:
        print(ERROR + "\nCouldn't process input file - are you sure you gave a file containing a tcpdump pcap or wireshark c_arrays?"+ CLEAR)
        exit()

    print(SUCCESS + "Processed input file %s" % (INPUT_FILE_PATH)+ CLEAR)


def processPcap(inputFile: object):
    '''
    ingests pcap using scapy and parses client-server communication to populate FUZZER_DATA 
    with message sequences that we can use as a baseline for our fuzzing
    '''
    global LAST_MESSAGE_DIRECTION, FUZZER_DATA, DEFAULT_PORT
    clientPort = None
    serverPort = None
    
    inputData = scapy.all.rdpcap(INPUT_FILE_PATH)

    j = -1
    for i in range(0, len(inputData)):
        try:
            if not clientPort:
                # First packet will usually but not always come from client
                # Use port instead of ip/MAC in case we're fuzzing on the same machine as the daemon
                # Guess at right port based, confirm to user
                port1 = inputData[i].sport
                port2 = inputData[i].dport
                
                # IF port1 == port2, then it can't be the same ip/MAC, so go based on that
                useMacs = False
                if port1 == port2:
                    print("Source and destination ports are the same, using MAC addresses to differentiate server and client.")
                    useMacs = True
                    mac1 = inputData[i].src
                    mac2 = inputData[i].dst
            
                serverPort = port2
                if useMacs:
                    serverMac = mac2
                if not FORCE_DEFAULTS: 
                    if not useMacs:
                        serverPort = int(prompt("Which port is the server listening on?", [str(port2), str(port1)], defaultIndex=0 if port1 > port2 else 1))
                    else:
                        serverMac = prompt("Which mac corresponds to the server?", [str(mac1), str(mac2)], defaultIndex=1)

                clientPort = port1 if serverPort == port2 else port2
                if useMacs:
                    clientMac = mac1 if serverMac == mac2 else mac2
                DEFAULT_PORT = serverPort
            elif inputData[i].sport not in [clientPort, serverPort]:
                print("Error: unknown source port %d - is the capture filtered to a single stream?" % (inputData[i].sport))
            elif inputData[i].dport not in [clientPort, serverPort]:
                print("Error: unknown destination port %d - is the capture filtered to a single stream?" % (inputData[i].dport))
            
            if not useMacs:
                newMessageDirection = Message.Direction.Outbound if inputData[i].sport == clientPort else Message.Direction.Inbound
            else:
                newMessageDirection = Message.Direction.Outbound if inputData[i].src == clientMac else Message.Direction.Inbound

            try:
                # This appear to work for UDP.  Go figure, thanks scapy.
                tempMessageData = bytes(inputData[i].payload.payload.payload)
            except AttributeError:
                tempMessageData = ""
            if len(tempMessageData) == 0:
                # This appears to work for TCP
                tempMessageData = inputData[i].load

            if newMessageDirection == LAST_MESSAGE_DIRECTION:
                if FORCE_DEFAULTS:
                   isCombiningPackets = True 
                   askedToCombinePackets = True
                if not askedToCombinePackets:
                    if prompt("There are multiple packets from client to server or server to client back-to-back - combine payloads into single messages?"):
                        isCombiningPackets = True
                    askedToCombinePackets = True
                if isCombiningPackets:
                    message.appendMessageFrom(Message.Format.Raw, bytearray(tempMessageData), False)
                    print(SUCCESS + "\tMessage #%d - Added %d new bytes %s" % (j, len(tempMessageData), message.direction) + CLEAR)
                    continue
            # Either direction isn't the same or we're not combining packets
            message = Message()
            message.direction = newMessageDirection
            LAST_MESSAGE_DIRECTION = newMessageDirection
            message.setMessageFrom(Message.Format.Raw, bytearray(tempMessageData), False)
            FUZZER_DATA.messageCollection.addMessage(message)
            j += 1
            print(SUCCESS + "\tMessage #%d - Processed %d bytes %s" % (j, len(message.getOriginalMessage()), message.direction) + CLEAR)
        except AttributeError:
            # No payload, keep going (different from empty payload)
            continue

def processCArray(inputFile: object):
    '''
    Process and convert c_array into .fuzzer
    This is processing the wireshark syntax looking like:

    char peer0_0[] = { 0x66, 0x64, 0x73, 0x61, 0x0a };
    char peer1_0[] = { 0x61, 0x73, 0x64, 0x66, 0x0a };

    First is message from client to server, second is server to client
    Format is peer0/1_messagenum
    0 = client, 1 = server
    '''
    global LAST_MESSAGE_DIRECTION

    i = 0
    for line in inputFile:
        #remove comments
        com_start,com_end = line.find('/*'),line.rfind('*/')
        if com_start > -1 and com_end > -1:
            line = line[:com_start] + line[com_end+2:]

        if state == STATE_BETWEEN_MESSAGES:
            # On a new message, seek inputData
            message = Message()
            tempMessageData = ""
            
            peerPos = line.find("peer")
            if peerPos == -1:
                continue
            elif line[peerPos+4] == str(0):
                message.direction = Message.Direction.Outbound
            elif line[peerPos+4] == str(1):
                message.direction = Message.Direction.Inbound
            else:
                continue
            
            bracePos = line.find("{")
            if bracePos == -1:
                continue
            tempMessageData += line[bracePos+1:]
            state = STATE_READING_MESSAGE
            
            # Sometimes HTTP requests, etc, get separated into multiple packets but they should
            # really be treated as one message.  Allow the user to decide to do this automatically
            if message.direction == LAST_MESSAGE_DIRECTION:
                if FORCE_DEFAULTS:
                    askedToCombinePackets=True
                    isCombiningPackets=True
                if not askedToCombinePackets:
                    if prompt("There are multiple packets from client to server or server to client back-to-back - combine payloads into single messages?"):
                        isCombiningPackets = True
                    askedToCombinePackets = True
                if isCombiningPackets:
                    message = FUZZER_DATA.messageCollection.messages[-1]
                    state = STATE_COMBINING_PACKETS
        elif state == STATE_READING_MESSAGE or state == STATE_COMBINING_PACKETS:
            bracePos = line.find("}")
            if bracePos == -1:
                # No close brace means keep reading
                tempMessageData += line
            else:
                # Close brace means save the message
                tempMessageData += line[:bracePos]
                # Turn list of comma&space-separated bytes into a string of 0x hex bytes
                messageArray = tempMessageData.replace(",", "").replace("0x", "").split()
                
                if state == STATE_READING_MESSAGE:
                    message.setMessageFrom(Message.Format.CommaSeparatedHex, ",".join(messageArray), False)
                    FUZZER_DATA.messageCollection.addMessage(message)
                    print("\tMessage #%d - Processed %d bytes %s" % (i, len(messageArray), message.direction))
                elif state == STATE_COMBINING_PACKETS:
                    # Append new inputData to last message
                    i -= 1
                    message.appendMessageFrom(Message.Format.CommaSeparatedHex, ",".join(messageArray), False, createNewSubcomponent=False)
                    print("\tMessage #%d - Added %d new bytes %s" % (i, len(messageArray), message.direction))
                if args.dump_ascii:
                    print("\tAscii: %s" % (str(message.getOriginalMessage())))
                i += 1
                state = STATE_BETWEEN_MESSAGES
                LAST_MESSAGE_DIRECTION = message.direction


def genFuzzConfig():
    '''
    Get fuzzing details 
    '''
    global FUZZER_DATA

    # Ask how many times we should repeat a failed test, as in one causing a crash
    FUZZER_DATA.failureThreshold = promptInt("\nHow many times should a test case causing a crash or error be repeated?", defaultResponse=3) if not FORCE_DEFAULTS else 3
    # Timeout between failure retries
    FUZZER_DATA.failureTimeout = promptInt("When the test case is repeated above, how many seconds should it wait between tests?", defaultResponse=5) if not FORCE_DEFAULTS else 5
    # Ask if tcp or udp
    FUZZER_DATA.proto = prompt("Which protocol?", answers=["tcp", "udp", "layer3" ], defaultIndex=0) if not FORCE_DEFAULTS else "tcp"

    # for finding out which L3 protocol
    if FUZZER_DATA.proto == "layer3":
        FUZZER_DATA.proto = prompt("Which layer3 protocol?", answers=["icmp","igmp","ipv4","tcp","igp","udp","ipv6","ipv6-route","ipv6-frag","gre", \
                                                                     "dsr","esp","ipv6-icmp","ipv6-nonxt","ipv6-opts","eigrp","ospf","mtp","l2tp","sctp","manual"],defaultIndex=0)
    # in the case that it's not in the above list
    if FUZZER_DATA.proto == "manual":
        FUZZER_DATA.proto = promptInt("What is the L3 protocol number?", defaultResponse=0)    

    # Port number to connect on
    FUZZER_DATA.port = promptInt("What port should the fuzzer %s?" % ("connect to"), defaultResponse=DEFAULT_PORT) if not FORCE_DEFAULTS else DEFAULT_PORT

    # How many of the messages to output to the .fuzzer
    default = len(FUZZER_DATA.messageCollection.messages)-1

def writeFuzzerFile():
    '''
    writes FUZZER_DATA to a new .fuzzer file using promptAndOutput()
    '''
    # See if they'd like us to just rip out a .fuzzer per client message
    # Default to no
    if prompt("\nWould you like to auto-generate a .fuzzer for each client message?", defaultIndex=1):
        promptAndOutput(getNextMessage(0, Message.Direction.Outbound), autogenerateAllClient=True)
    else:
        # Always run once
        outputMessageNum = promptAndOutput(getNextMessage(0, Message.Direction.Outbound))

        # Allow creating multiple .fuzzers afterwards
        if not FORCE_DEFAULTS:
            while prompt("\nDo you want to generate a .fuzzer for another message number?", defaultIndex=1):
                outputMessageNum = promptAndOutput(outputMessageNum)
    print(SUCCESS + "All files have been written." + CLEAR)


def getNextMessage(startMessage, messageDirection):
    '''
    Helper function to get next message from either client or server
    Inclusive (if startMessage is fromClient and so is direction,
    will return startMessage)
    Returns message number or None if no messages remain
    '''
    i = startMessage
    
    while i < len(FUZZER_DATA.messageCollection.messages):
        if FUZZER_DATA.messageCollection.messages[i].direction == messageDirection:
            return i
        i += 1
    
    return None

def promptAndOutput(outputMessageNum: int, autogenerateAllClient: bool = False):
    '''
    Prompt for .fuzzer-specific questions and write file (calls above function)
    Allows us to let the user crank out a bunch of .fuzzer files quickly
    outputMessageNum is the highest message output last time, if they're creating multiple .fuzzer files
    autogenerateAllClient will make a .fuzzer file per client automatically
    '''
    global FUZZER_DATA
    # How many of the messages to output to the .fuzzer
    if FORCE_DEFAULTS or autogenerateAllClient:
        finalMessageNum = len(FUZZER_DATA.messageCollection.messages)-1
    else:
        finalMessageNum = promptInt("What is the last message number you want output?", defaultResponse=len(FUZZER_DATA.messageCollection.messages)-1)

    # Any messages previously marked for fuzzing, unmark first
    # Inefficient as can be, but who cares
    for message in FUZZER_DATA.messageCollection.messages:
        if message.isFuzzed:
            message.isFuzzed = False
            for subcomponent in message.subcomponents:
                subcomponent.isFuzzed = False
    
    if not autogenerateAllClient:
        while True:
            tmp = promptString("Which message numbers should be fuzzed? Valid: 0-%d" % (finalMessageNum),defaultResponse=str(outputMessageNum),validateFunc=validateNumberRange)
            if len(tmp) > 0:
                outputFilenameEnd = tmp
                for messageIndex in validateNumberRange(tmp, flattenList=True):
                    FUZZER_DATA.messageCollection.messages[messageIndex].isFuzzed = True
                    for subcomponent in FUZZER_DATA.messageCollection.messages[messageIndex].subcomponents:
                        subcomponent.isFuzzed = True
                break
    else:
        outputFilenameEnd = str(outputMessageNum)
        FUZZER_DATA.messageCollection.messages[outputMessageNum].isFuzzed = True
        for subcomponent in FUZZER_DATA.messageCollection.messages[outputMessageNum].subcomponents:
            subcomponent.isFuzzed = True


    outputFilePath = "{0}-{1}.fuzzer".format(os.path.splitext(INPUT_FILE_PATH)[0], outputFilenameEnd)
    actualPath = FUZZER_DATA.writeToFile(outputFilePath, defaultComments=True, finalMessageNum=finalMessageNum)
    print(SUCCESS + "Wrote .fuzzer file: {0}".format(actualPath) + CLEAR)
    
    if autogenerateAllClient:
        nextMessage = getNextMessage(outputMessageNum+1, Message.Direction.Outbound)
        # Will return None when we're out of messages to auto-output
        if nextMessage:
            promptAndOutput(nextMessage, autogenerateAllClient=True)
    return finalMessageNum


