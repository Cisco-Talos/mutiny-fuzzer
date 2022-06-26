#!/usr/bin/env python
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
# This script takes pcap or c_arrays output from Wireshark and 
# processes it into a .fuzzer file for use with mutiny.py
#------------------------------------------------------------------
import os
import sys
import argparse

from backend.fuzzer_types import Message
from backend.menu_functions import prompt, promptInt, promptString, validateNumberRange
from backend.fuzzerdata import FuzzerData
import scapy.all

GREEN = "\033[92m"
CLEAR = "\033[00m"

#So argparse prints help if no args are given
if len(sys.argv) == 1:
    sys.argv.append("-h")

parser = argparse.ArgumentParser()
parser.add_argument("pcap_file", 
                    help="Pcap/c_array output from wireshark")

parser.add_argument("-d","--processor_dir", 
                    help = "Location of custom pcap Message/exception/log/monitor processors if any, see appropriate *processor.py source in ./mutiny_classes/ for implimentation details",
                    nargs=1,
                    default=["default"])


parser.add_argument("-a", "--dump_ascii", 
                    help="Dump the ascii output from packets ", 
                    action="store_true",
                    default=False)

parser.add_argument("-f", "--force",
                    help="Take all default options",
                    action = "store_true",  
                    default=False) 

args = parser.parse_args()
inputFilePath = args.pcap_file

# This stores all the fuzzer data and will eventually write it to the .fuzzer file with comments
fuzzerData = FuzzerData()
fuzzerData.processorDirectory = args.processor_dir[0]

############# Process input files
if not os.path.isfile(inputFilePath):
    print("Cannot read input %s" % (inputFilePath))
    exit()

STATE_BETWEEN_MESSAGES = 0
STATE_READING_MESSAGE = 2
STATE_COMBINING_PACKETS = 3
data = []
defaultPort = None

with open(inputFilePath, 'r') as inputFile:
    # This is a little naive, but it works
    # These two get recreated frequently
    message = Message()
    tempMessageData = ""
    # Track what we're looking for
    state = STATE_BETWEEN_MESSAGES
    
    # Allow combining packets in same direction back-to-back into one message
    askedToCombinePackets = False
    isCombiningPackets = False
    lastMessageDirection = -1

    print("Processing %s..." % (inputFilePath))
    
    try:
        # Process as Pcap preferentially
        clientPort = None
        serverPort = None
        
        data = scapy.all.rdpcap(inputFilePath)

        j = -1
        
        for i in range(0, len(data)):
            try:
                if not clientPort:
                    # First packet will usually but not always come from client
                    # Use port instead of ip/MAC in case we're fuzzing on the same machine as the daemon
                    # Guess at right port based, confirm to user
                    port1 = data[i].sport
                    port2 = data[i].dport
                    
                    # IF port1 == port2, then it can't be the same ip/MAC, so go based on that
                    useMacs = False
                    if port1 == port2:
                        print("Source and destination ports are the same, using MAC addresses to differentiate server and client.")
                        useMacs = True
                        mac1 = data[i].src
                        mac2 = data[i].dst
                
                    serverPort = port2
                    if useMacs:
                        serverMac = mac2
                    if not args.force: 
                        if not useMacs:
                            serverPort = int(prompt("Which port is the server listening on?", [str(port2), str(port1)], defaultIndex=0 if port1 > port2 else 1))
                        else:
                            serverMac = prompt("Which mac corresponds to the server?", [str(mac1), str(mac2)], defaultIndex=1)

                    clientPort = port1 if serverPort == port2 else port2
                    if useMacs:
                        clientMac = mac1 if serverMac == mac2 else mac2
                    defaultPort = serverPort
                elif data[i].sport not in [clientPort, serverPort]:
                    print("Error: unknown source port %d - is the capture filtered to a single stream?" % (data[i].sport))
                elif data[i].dport not in [clientPort, serverPort]:
                    print("Error: unknown destination port %d - is the capture filtered to a single stream?" % (data[i].dport))
                
                if not useMacs:
                    newMessageDirection = Message.Direction.Outbound if data[i].sport == clientPort else Message.Direction.Inbound
                else:
                    newMessageDirection = Message.Direction.Outbound if data[i].src == clientMac else Message.Direction.Inbound

                try:
                    # This appear to work for UDP.  Go figure, thanks scapy.
                    tempMessageData = bytes(data[i].payload.payload.payload)
                except AttributeError:
                    tempMessageData = ""
                if len(tempMessageData) == 0:
                    # This appears to work for TCP
                    tempMessageData = data[i].load

                if newMessageDirection == lastMessageDirection:
                    if args.force:
                       isCombiningPackets = True 
                       askedToCombinePackets = True
                    if not askedToCombinePackets:
                        if prompt("There are multiple packets from client to server or server to client back-to-back - combine payloads into single messages?"):
                            isCombiningPackets = True
                        askedToCombinePackets = True
                    if isCombiningPackets:
                        message.appendMessageFrom(Message.Format.Raw, bytearray(tempMessageData), False)
                        print("\tMessage #%d - Added %d new bytes %s" % (j, len(tempMessageData), message.direction))
                        continue
                # Either direction isn't the same or we're not combining packets
                message = Message()
                message.direction = newMessageDirection
                lastMessageDirection = newMessageDirection
                message.setMessageFrom(Message.Format.Raw, bytearray(tempMessageData), False)
                fuzzerData.messageCollection.addMessage(message)
                j += 1
                print("\tMessage #%d - Processed %d bytes %s" % (j, len(message.getOriginalMessage()), message.direction))
            except AttributeError:
                # No payload, keep going (different from empty payload)
                continue
    except Exception as rdpcap_e:
        print(str(rdpcap_e))
        print("Processing as c_array...")
        try:
            # Process c_arrays
            # This is processing the wireshark syntax looking like:
            # char peer0_0[] = {
            # 0x66, 0x64, 0x73, 0x61, 0x0a };
            # char peer1_0[] = {
            # 0x61, 0x73, 0x64, 0x66, 0x0a };
            # First is message from client to server, second is server to client
            # Format is peer0/1_messagenum
            # 0 = client, 1 = server
            i = 0
            for line in inputFile:

                #remove comments
                com_start,com_end = line.find('/*'),line.rfind('*/')
                if com_start > -1 and com_end > -1:
                    line = line[:com_start] + line[com_end+2:]

                if state == STATE_BETWEEN_MESSAGES:
                    # On a new message, seek data
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
                    if message.direction == lastMessageDirection:
                        if args.force:
                            askedToCombinePackets=True
                            isCombiningPackets=True
                        if not askedToCombinePackets:
                            if prompt("There are multiple packets from client to server or server to client back-to-back - combine payloads into single messages?"):
                                isCombiningPackets = True
                            askedToCombinePackets = True
                        if isCombiningPackets:
                            message = fuzzerData.messageCollection.messages[-1]
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
                            fuzzerData.messageCollection.addMessage(message)
                            print("\tMessage #%d - Processed %d bytes %s" % (i, len(messageArray), message.direction))
                        elif state == STATE_COMBINING_PACKETS:
                            # Append new data to last message
                            i -= 1
                            message.appendMessageFrom(Message.Format.CommaSeparatedHex, ",".join(messageArray), False, createNewSubcomponent=False)
                            print("\tMessage #%d - Added %d new bytes %s" % (i, len(messageArray), message.direction))
                        if args.dump_ascii:
                            print("\tAscii: %s" % (str(message.getOriginalMessage())))
                        i += 1
                        state = STATE_BETWEEN_MESSAGES
                        lastMessageDirection = message.direction
        except Exception as e:
            print("Unable to parse as pcap: %s" % (str(rdpcap_e)))
            print("Unable to parse as c_arrays: %s" % (str(e)))

if len(fuzzerData.messageCollection.messages) == 0:
    print("\nCouldn't process input file - are you sure you gave a file containing a tcpdump pcap or wireshark c_arrays?")
    exit()
print("Processed input file %s" % (inputFilePath))

############# Get fuzzing details 
# Ask how many times we should repeat a failed test, as in one causing a crash
fuzzerData.failureThreshold = promptInt("\nHow many times should a test case causing a crash or error be repeated?", defaultResponse=3) if not args.force else 3
# Timeout between failure retries
fuzzerData.failureTimeout = promptInt("When the test case is repeated above, how many seconds should it wait between tests?", defaultResponse=5) if not args.force else 5
# Ask if tcp or udp
fuzzerData.proto = prompt("Which protocol?", answers=["tcp", "udp", "layer3" ], defaultIndex=0) if not args.force else "tcp"

# for finding out which L3 protocol
if fuzzerData.proto == "layer3":
    fuzzerData.proto = prompt("Which layer3 protocol?", answers=["icmp","igmp","ipv4","tcp","igp","udp","ipv6","ipv6-route","ipv6-frag","gre", \
                                                                 "dsr","esp","ipv6-icmp","ipv6-nonxt","ipv6-opts","eigrp","ospf","mtp","l2tp","sctp","manual"],defaultIndex=0)
# in the case that it's not in the above list
if fuzzerData.proto == "manual":
    fuzzerData.proto = promptInt("What is the L3 protocol number?", defaultResponse=0)    

# Port number to connect on
fuzzerData.port = promptInt("What port should the fuzzer %s?" % ("connect to"), defaultResponse=defaultPort) if not args.force else defaultPort

# How many of the messages to output to the .fuzzer
default = len(fuzzerData.messageCollection.messages)-1

######################################################

############# Helper function to get next message from either client or server
# Inclusive (if startMessage is fromClient and so is direction,
# will return startMessage)
# Returns message number or None if no messages remain
def getNextMessage(startMessage, messageDirection):
    i = startMessage
    
    while i < len(fuzzerData.messageCollection.messages):
        if fuzzerData.messageCollection.messages[i].direction == messageDirection:
            return i
        i += 1
    
    return None

############# Prompt for .fuzzer-specific questions and write file (calls above function)
# Allows us to let the user crank out a bunch of .fuzzer files quickly
# Param is the highest message output last time, if they're creating multiple .fuzzer files
# autogenerateAllClient will make a .fuzzer file per client automatically
def promptAndOutput(outputMessageNum, autogenerateAllClient=False):
    # How many of the messages to output to the .fuzzer
    if args.force or autogenerateAllClient:
        finalMessageNum = len(fuzzerData.messageCollection.messages)-1
    else:
        finalMessageNum = promptInt("What is the last message number you want output?", defaultResponse=len(fuzzerData.messageCollection.messages)-1)

    # Any messages previously marked for fuzzing, unmark first
    # Inefficient as can be, but who cares
    for message in fuzzerData.messageCollection.messages:
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
                    fuzzerData.messageCollection.messages[messageIndex].isFuzzed = True
                    for subcomponent in fuzzerData.messageCollection.messages[messageIndex].subcomponents:
                        subcomponent.isFuzzed = True
                break
    else:
        outputFilenameEnd = str(outputMessageNum)
        fuzzerData.messageCollection.messages[outputMessageNum].isFuzzed = True
        for subcomponent in fuzzerData.messageCollection.messages[outputMessageNum].subcomponents:
            subcomponent.isFuzzed = True


    outputFilePath = "{0}-{1}.fuzzer".format(os.path.splitext(inputFilePath)[0], outputFilenameEnd)
    actualPath = fuzzerData.writeToFile(outputFilePath, defaultComments=True, finalMessageNum=finalMessageNum)
    print(GREEN)
    print("Wrote .fuzzer file: {0}".format(actualPath))
    print(CLEAR)
    
    if autogenerateAllClient:
        nextMessage = getNextMessage(outputMessageNum+1, Message.Direction.Outbound)
        # Will return None when we're out of messages to auto-output
        if nextMessage:
            promptAndOutput(nextMessage, autogenerateAllClient=True)
    return finalMessageNum

############# Call promptAndOutput()

# See if they'd like us to just rip out a .fuzzer per client message
# Default to no
if prompt("\nWould you like to auto-generate a .fuzzer for each client message?", defaultIndex=1):
    promptAndOutput(getNextMessage(0, Message.Direction.Outbound), autogenerateAllClient=True)
else:
    # Always run once
    outputMessageNum = promptAndOutput(getNextMessage(0, Message.Direction.Outbound))

    # Allow creating multiple .fuzzers afterwards
    if not args.force:
        while prompt("\nDo you want to generate a .fuzzer for another message number?", defaultIndex=1):
            outputMessageNum = promptAndOutput(outputMessageNum)

print("All files have been written.")
