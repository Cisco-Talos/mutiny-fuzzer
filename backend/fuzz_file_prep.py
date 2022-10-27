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
from backend.fuzzer_types import Message, MessageCollection, Logger
from backend.menu_functions import prompt, promptInt, promptString, validateNumberRange
from backend.fuzzer_data import FuzzerData
from backend.packets import PROTO
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
DUMP_ASCII = False
INPUT_FILE_PATH = ""
DEFAULT_PORT = None
FUZZER_DATA = None
# Did the user specify the -raw flag to do L2?
IS_RAW = False
# If it's C Arrays, we ask for the protocol in the prompts
IS_CARRAYS = False

def print_error(message):
    print(f'{ERROR}{message}{CLEAR}')

def print_success(message):
    print(f'{SUCCESS}{message}{CLEAR}')

def prep(args: argparse.Namespace):
    '''
    facilitates
    1. processing of user specified pcap or C_array file
    2. user configuration of .fuzzer format
    3. creation of the .fuzzer file
    '''
    global  INPUT_FILE_PATH, FORCE_DEFAULTS, FUZZER_DATA, DUMP_ASCII, IS_RAW
    INPUT_FILE_PATH = args.pcap_file
    FORCE_DEFAULTS = args.force
    DUMP_ASCII = args.dump_ascii
    IS_RAW = args.raw

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
        print_error('Cannot read input {INPUT_FILE_PATH}')
        exit()

    with open(INPUT_FILE_PATH, 'r') as inputFile:
        print("Processing %s..." % (INPUT_FILE_PATH))
        try:
            processPcap(inputFile) # Process as Pcap preferentially
        except Exception as rdpcap_e:
            print(WARNING + "Failed to process as PCAP: " +  str(rdpcap_e) + CLEAR)
            IS_CARRAYS = True
            print("Processing as c_array...")
            try:
                processCArray(inputFile)
            except Exception as e:
                print_error('''Can't parse as pcap or c_arrays:''')
                print_error(f'Pcap parsing error: {str(rdpcap_e)}')
                print_error(f'Not valid c_arrays: {str(e)}')

    if len(FUZZER_DATA.messageCollection.messages) == 0:
        print_error('\nCouldn\'t process input file - are you sure you gave a file containing a tcpdump pcap or wireshark c_arrays?')
        exit()

    print_success(f'Processed input file {INPUT_FILE_PATH}')

def processFirstPcapPacket(packet, useMacs, testPort, testMac):
    global FUZZER_DATA, DEFAULT_PORT
    if IS_RAW:
        FUZZER_DATA.proto = 'L2raw'
        print('Pulling layer 2+ data from pcap to use with raw sockets')
    else:
        if packet.proto == PROTO['udp']:
            FUZZER_DATA.proto = 'udp'
            print('Protocol is UDP')
        elif packet.proto == PROTO['tcp']:
            FUZZER_DATA.proto = 'tcp'
            print('Protocol is TCP')
        else:
            print_error(f'Error: First packet has protocol {inputData[i].proto} - Did you mean to do set "--raw" for Layer 2 fuzzing?')
            exit()
        # is not a raw socket, can grab ports
        # First packet will usually but not always come from client
        # Use port instead of ip/MAC in case we're fuzzing on the same machine as the daemon
        # Guess at right port based, confirm to user
        srcPort = packet.sport
        dstPort = packet.dport
        # If port1 == port2, then it can't be the same ip/MAC, so go based on that
        if srcPort == dstPort:
            print("Source and destination ports are the same, using MAC addresses to differentiate server and client.")
            useMacs = True
    # either raw or ports are the same
    if useMacs:
        srcMac = packet.src
        dstMac = packet.dst
        serverMac = dstMac
        if not FORCE_DEFAULTS:
            if testMac:
                serverMac = testMac
            else:
                serverMac = prompt("Which mac corresponds to the server?", [str(srcMac), str(dstMac)], defaultIndex=1)
        clientMac = srcMac if serverMac == dstMac else dstMac
        return useMacs, clientMac, serverMac
    else:
        # under assumption that client sent first packet 
        serverPort = dstPort
        if not FORCE_DEFAULTS: 
            if testPort:
                serverPort = testPort
            else:
                serverPort = int(prompt("Which port is the server listening on?", [str(dstPort), str(srcPort)], defaultIndex=0 if srcPort > dstPort else 1))

        clientPort = srcPort if serverPort == dstPort else dstPort
        DEFAULT_PORT = serverPort
        return False, clientPort, serverPort

def processPcap(inputFile: object, testPort: int = None, testMac: str = None, combinePackets: bool = None):
    '''
    ingests pcap using scapy and parses client-server communication to populate FUZZER_DATA 
    with message sequences that we can use as a baseline for our fuzzing
    '''
    global LAST_MESSAGE_DIRECTION, FUZZER_DATA, DEFAULT_PORT
    clientPort = None
    serverPort = None
    clientMac = None
    serverMac = None
    
    inputData = scapy.all.rdpcap(INPUT_FILE_PATH)
    message = Message()
    tempMessageData = ""
    # Allow combining packets in same direction back-to-back into one message
    askedToCombinePackets = False
    isCombiningPackets = False
    useMacs = IS_RAW

    j = -1
    for i in range(0, len(inputData)):
        try:
            # first packet
            if i == 0:
                useMacs, srcHost, dstHost = processFirstPcapPacket(inputData[i], useMacs, testPort, testMac)
                if useMacs:
                    clientMac = srcHost 
                    serverMac = dstHost
                else:
                    clientPort = srcHost
                    serverPort = dstHost
            elif not useMacs and inputData[i].sport not in [clientPort, serverPort]:
                print_error(f'Error: unknown source port {inputData[i].sport} - is the capture filtered to a single stream?')
            elif not useMacs and inputData[i].dport not in [clientPort, serverPort]:
                print_error(f'Error: unknown destination port {inputData[i].dport} - is the capture filtered to a single stream?')
            # TODO: we don't have any sort of checking to make sure a l2raw capture is single stream 
            if not useMacs:
                newMessageDirection = Message.Direction.Outbound if inputData[i].sport == clientPort else Message.Direction.Inbound
            else:
                newMessageDirection = Message.Direction.Outbound if inputData[i].src == clientMac else Message.Direction.Inbound

            if FUZZER_DATA.proto == 'udp':
                # This appear to work for UDP.  Go figure, thanks scapy.
                tempMessageData = bytes(inputData[i].payload.payload.payload)
            elif FUZZER_DATA.proto == 'tcp': 
                # This appears to work for TCP
                tempMessageData = bytes(inputData[i].payload.payload.payload)
                if tempMessageData == b'': continue
            elif FUZZER_DATA.proto == 'L2raw': 
                tempMessageData = bytes(inputData[i])
            else:
                print_error(f'Error: Fuzzer data has an unknown protocol {FUZZER_DATA.proto} - should be impossible?')
                exit()

            if newMessageDirection == LAST_MESSAGE_DIRECTION:
                if FORCE_DEFAULTS:
                   isCombiningPackets = True 
                   askedToCombinePackets = True
                if not askedToCombinePackets:
                    if combinePackets is not None:
                        isCombiningPackets = combinePackets
                    else:
                        isCombiningPackets =  prompt("There are multiple packets from client to server or server to client back-to-back - combine payloads into single messages?")
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

def processCArray(inputFile: object, combinePackets: bool = None):
    '''
    Process and convert c_array into .fuzzer
    This is processing the wireshark syntax looking like:

    char peer0_0[] = { 0x66, 0x64, 0x73, 0x61, 0x0a };
    char peer1_0[] = { 0x61, 0x73, 0x64, 0x66, 0x0a };

    First is message from client to server, second is server to client
    Format is peer0/1_messagenum
    0 = client, 1 = server
    '''
    global LAST_MESSAGE_DIRECTION, FUZZER_DATA

    LAST_MESSAGE_DIRECTION = None
    state = STATE_BETWEEN_MESSAGES # Track what we're looking for
    # Allow combining packets in same direction back-to-back into one message
    askedToCombinePackets = False
    isCombiningPackets = False

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
            state = STATE_READING_MESSAGES
            
            # Sometimes HTTP requests, etc, get separated into multiple packets but they should
            # really be treated as one message.  Allow the user to decide to do this automatically
            if message.direction == LAST_MESSAGE_DIRECTION:
                if FORCE_DEFAULTS:
                    askedToCombinePackets=True
                    isCombiningPackets=True
                if not askedToCombinePackets:
                    if combinePackets is not None:
                        isCombiningPackets = combinePackets
                    else:
                        isCombiningPackets = prompt("There are multiple packets from client to server or server to client back-to-back - combine payloads into single messages?")
                    askedToCombinePackets = True
                if isCombiningPackets:
                    message = FUZZER_DATA.messageCollection.messages[-1]
                    state = STATE_COMBINING_PACKETS
        elif state == STATE_READING_MESSAGES or state == STATE_COMBINING_PACKETS:
            bracePos = line.find("}")
            if bracePos == -1:
                # No close brace means keep reading
                tempMessageData += line
            else:
                # Close brace means save the message
                tempMessageData += line[:bracePos]
                # Turn list of comma&space-separated bytes into a string of 0x hex bytes
                messageArray = tempMessageData.replace(",", "").replace("0x", "").split()
                if state == STATE_READING_MESSAGES:
                    message.setMessageFrom(Message.Format.CommaSeparatedHex, ",".join(messageArray), False)
                    FUZZER_DATA.messageCollection.addMessage(message)
                    print("\tMessage #%d - Processed %d bytes %s" % (i, len(messageArray), message.direction))
                elif state == STATE_COMBINING_PACKETS:
                    # Append new inputData to last message
                    i -= 1
                    message.appendMessageFrom(Message.Format.CommaSeparatedHex, ",".join(messageArray), False, createNewSubcomponent=False)
                    print("\tMessage #%d - Added %d new bytes %s" % (i, len(messageArray), message.direction))
                if DUMP_ASCII:
                    print("\tAscii: %s" % (str(message.getOriginalMessage())))
                i += 1
                state = STATE_BETWEEN_MESSAGES
                LAST_MESSAGE_DIRECTION = message.direction


def genFuzzConfig(failureThreshold: int = None, failureTimeout: int = None, proto: str = None, port: int = None):
    '''
    get fuzzing details 
    '''
    global FUZZER_DATA

    if FORCE_DEFAULTS:
        FUZZER_DATA.port = DEFAULT_PORT
        FUZZER_DATA.failureThreshold = 3
        FUZZER_DATA.failureTimeout = 5
        FUZZER_DATA.proto = 'tcp'
    else:
        # ask how many times we should repeat a failed test, as in one causing a crash
        FUZZER_DATA.failureThreshold = failureThreshold if failureThreshold else promptInt("\nHow many times should a test case causing a crash or error be repeated?", defaultResponse=3)
        # timeout between failure retries
        FUZZER_DATA.failureTimeout = failureTimeout if failureTimeout else promptInt("When the test case is repeated above, how many seconds should it wait between tests?", defaultResponse=5)
        if not IS_RAW:
            # port number to connect on
            FUZZER_DATA.port = port if port else promptInt("What port should the fuzzer %s?" % ("connect to"), defaultResponse=DEFAULT_PORT)
        
        # For pcaps, we pull protocol from the pcap itself
        if IS_CARRAYS:
            if IS_RAW:
                FUZZER_DATA.proto = "L2raw"
            else:
                # ask if tcp or udp
                FUZZER_DATA.proto = proto if proto else prompt("Which protocol?", answers=["tcp", "udp"], defaultIndex=0)

    if not IS_RAW and FUZZER_DATA.port == None:
        # address case where CArray does not set default port
        FUZZER_DATA.port = -1
        while(FUZZER_DATA.port <= 0 or FUZZER_DATA.port >= 65535):
            FUZZER_DATA.port = promptInt("What port should the fuzzer %s?" % ("connect to"))


def writeFuzzerFile(autogen:bool = None):
    '''
    writes FUZZER_DATA to a new .fuzzer file using promptAndOutput()
    '''
    # see if they'd like us to just rip out a .fuzzer per client message
    # default to no
    autogen = autogen if autogen is not None else prompt("\nWould you like to auto-generate a .fuzzer for each client message?", defaultIndex=1)
    if autogen:
        promptAndOutput(getNextMessage(0, Message.Direction.Outbound), autoGenerateAllClient=True)
    else:
        # always run once
        outputMessageNum = promptAndOutput(getNextMessage(0, Message.Direction.Outbound))

        # allow creating multiple .fuzzers afterwards
        if not FORCE_DEFAULTS:
            while prompt("\nDo you want to generate a .fuzzer for another message number?", defaultIndex=1):
                outputMessageNum = promptAndOutput(outputMessageNum)
    print(SUCCESS + "All files have been written." + CLEAR)


def getNextMessage(startMessage: int, messageDirection: Message.Direction):
    '''
    helper function to get next message from either client or server
    inclusive (if startmessage is fromclient and so is direction,
    will return startmessage)
    returns message number or none if no messages remain
    '''
    i = startMessage
    
    while i < len(FUZZER_DATA.messageCollection.messages):
        if FUZZER_DATA.messageCollection.messages[i].direction == messageDirection:
            return i
        i += 1
    
    return None

def promptAndOutput(outputMessageNum: int, autoGenerateAllClient: bool = False, finalMsgNum: int = None, msgsToFuzz: str = None):
    '''
    prompt for .fuzzer-specific questions and write file (calls above function)
    allows us to let the user crank out a bunch of .fuzzer files quickly
    outputMessageNum is the highest message output last time, if they're creating multiple .fuzzer files
    autoGenerateAllClient will make a .fuzzer file per client automatically
    '''
    global FUZZER_DATA
    # how many of the messages to output to the .fuzzer
    if FORCE_DEFAULTS or autoGenerateAllClient:
        finalMessageNum = len(FUZZER_DATA.messageCollection.messages) - 1
    else:
        finalMessageNum = finalMsgNum if finalMsgNum else promptInt("What is the last message number you want output?", defaultResponse=len(FUZZER_DATA.messageCollection.messages)-1)

    # any messages previously marked for fuzzing, unmark first
    # inefficient as can be, but who cares
    for message in FUZZER_DATA.messageCollection.messages:
        if message.isFuzzed:
            message.isFuzzed = False
            for subcomponent in message.subcomponents:
                subcomponent.isFuzzed = False
    
    if not autoGenerateAllClient:
        messagesToFuzz = ''
        while len(messagesToFuzz) <= 0 or len(messagesToFuzz) > finalMessageNum:
            messagesToFuzz = msgsToFuzz if msgsToFuzz else promptString("Which message numbers should be fuzzed? valid: 0-%d" % (finalMessageNum),defaultResponse=str(outputMessageNum),validateFunc=validateNumberRange)
        # len of messagesToFuzz must now be between 0 and finalMessageNum
        outputFileNameEnd = messagesToFuzz
        # iterate through messages and set .isFuzzed on subcomponents
        for messageIndex in validateNumberRange(messagesToFuzz, flattenList=True):
            FUZZER_DATA.messageCollection.messages[messageIndex].isFuzzed = True
            for subcomponent in FUZZER_DATA.messageCollection.messages[messageIndex].subcomponents:
                subcomponent.isFuzzed = True
    else:
        outputFileNameEnd = str(outputMessageNum)
        # set message at outputMessageNum and all subcomponents .isFuzzed to true
        FUZZER_DATA.messageCollection.messages[outputMessageNum].isFuzzed = True
        for subcomponent in FUZZER_DATA.messageCollection.messages[outputMessageNum].subcomponents:
            subcomponent.isFuzzed = True

    # write out .fuzzer file
    outputfilepath = "{0}-{1}.fuzzer".format(os.path.splitext(INPUT_FILE_PATH)[0], outputFileNameEnd)
    actualpath = FUZZER_DATA.writeToFile(outputfilepath, defaultComments=True, finalMessageNum=finalMessageNum)
    print(SUCCESS + "Wrote .fuzzer file: {0}".format(actualpath) + CLEAR)
    
    # if we are fuzzing all client messages, continue to recursively call promptAndOutput for next message
    if autoGenerateAllClient:
        nextmessage = getNextMessage(outputMessageNum + 1, Message.Direction.Outbound)
        # will return none when we're out of messages to auto-output
        if nextmessage:
            promptAndOutput(nextmessage, autoGenerateAllClient=True)
    return finalMessageNum


