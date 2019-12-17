#!/usr/bin/env python2
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
# This is the main fuzzing script
#
# This script takes a .fuzzer file and performs the actual fuzzing
#------------------------------------------------------------------

import os
import imp
import sys
import time
import errno
import signal
import socket
import os.path
import datetime
import argparse
import threading
import subprocess

from re import match
from copy import deepcopy
from backend.packets import PROTO,IP
from backend.fuzzerdata import FuzzerData
from backend.proc_director import ProcDirector
from backend.menu_functions import validateNumberRange
from backend.fuzzer_types import Message, MessageCollection, Logger
from mutiny_classes.mutiny_exceptions import *

# Path to Radamsa binary
RADAMSA=os.path.abspath( os.path.join(__file__, "..","radamsa","bin","radamsa") )
# Whether to print debug info
DEBUG_MODE=False


class MutinyFuzzer():

    def __init__(self,args):

        self.args = args
        # Test number to start from, 0 default
        self.MIN_RUN_NUMBER=0
        # Test number to go to, -1 is unlimited
        self.MAX_RUN_NUMBER=-1
        # For seed loop, finite range to repeat   
        self.SEED_LOOP = []
        # For dumpraw option, dump into log directory by default, else 'dumpraw'
        self.DUMPDIR = ""

        # Output => pretty. Yay.
        self.banner_messages = ["**********The Mutiny Fuzzing Framework**********",CYAN  + "jaspadar@cisco.com" + \
                                                                GREEN + " && " \
                                                              + PURPLE + "liwyatt@cisco.com <(^_^)>"+CLEAR+"|" ]
        self.important_messages = []
        self.fuzzer_messages = []

        self.window_height,self.window_width = os.popen('stty size', 'r').read().split()

        # used in makeConnector for slight speed up.
        self.socket_family = None
        #Populate global arguments from parseargs
        self.fuzzerFilePath = args.prepped_fuzz
         
        self.serverSocket = None
    
        self.host = args.target_host

        #Assign Lower/Upper bounds on test cases as needed
        if args.range:
            (self.MIN_RUN_NUMBER, self.MAX_RUN_NUMBER) = getRunNumbersFromArgs(args.range)
        elif args.loop:
            self.SEED_LOOP = validateNumberRange(args.loop,True) 

        # For POC dumping
        self.poc_packet_cache = []
        self.POC_PACKET_COLS = 80

        # Will wait till given the green light by campaign.py for each seed.
        # will also dump .fuzzer files of seeds that hit new bbs.
        self.campaign = False
        self.saved_fuzzy_message = ""

        self.mutator = args.mutator

        if args.campaign:
            self.campaign = True
            self.campaign_port = args.campaign
            self.ipc_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            self.ipc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                self.ipc_sock.bind(("127.0.0.1",self.campaign_port))
            except:
                pass
            self.ipc_sock.listen(1) 
            self.output("Waiting on connection from controlling campaign.py....")
            self.camp_sock,self.camp_sock_addr = self.ipc_sock.accept() 

        #Check for dependency binaries
        try:
            with open(self.mutator,"rb") as f:
                pass 
        except:
            print "Could not find mutator in %s... did you build it?" % self.mutator 
            raise


        #if args.campaign:
        #    raise FileNotFoundError("Could not find radamsa in %s... did you build it?" % RADAMSA)
            

        #Logging options
        self.isReproduce = True if args.quiet else False 
        
        self.fuzzerData = FuzzerData()

        try:
            self.fuzzerData.readFromFile(self.fuzzerFilePath,args.quiet)
        except Exception as e:
            self.output("Message Error: %s"%(e))
            # must have swapped file/host, oh well  
            self.fuzzerFilePath = args.target_host
            self.fuzzerData.readFromFile(self.fuzzerFilePath)
            self.host = args.prepped_fuzz
            self.args.target_host = args.prepped_fuzz
            
        self.output("[*] Reading in fuzzer data from %s..." % (self.fuzzerFilePath),CYAN)
        self.outputDataFolderPath = os.path.join("%s_%s" % (os.path.splitext(self.fuzzerFilePath)[0], "logs"), datetime.datetime.now().strftime("%Y-%m-%d,%H%M%S"))
        self.fuzzerFolder = os.path.abspath(os.path.dirname(self.fuzzerFilePath))

        # override the port if cmdline given. (for better scripting)
        if args.port > 0:
            self.fuzzerData.port = args.port

        if args.msgtofuzz:
            try:
                self.fuzzerData.setMessagesToFuzzFromString(args.msgtofuzz)
            except Exception as e:
                self.output("Message Error: %s"%str(e))
                exit()

        self.crash_socket = None
        if args.crashes:
            self.crash_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            try:
                crash_ip, crash_port = args.feedback.split(":") 
                self.output("[o.o] Binding crash socket @ %s:%d"%(crash_ip,int(crash_port)))
                self.crash_socket.bind((crash_ip,int(crash_port)))
                self.crash_socket.listen(1)
                self.crash_socket.settimeout(1)
                self.crash_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                
            except Exception as e:
                self.output("[x.x] Invalid --crash %s, format=> \"<ip>:<port>\", crash listener disabled"%args.feedback,YELLOW) 
                self.output(str(e))

                
        ######## Processor Setup ################
        # The processor just acts as a container #
        # class that will import custom versions #
        # messageProcessor/exceptionProessor/    #
        # monitor, if they are found in the      #
        # process_dir specified in the .fuzzer   #
        # file generated by fuzz_prep.py         #
        ##########################################

        # Assign options to variables, error on anything that's missing/invalid
        self.processorDirectory = self.fuzzerData.processorDirectory
        if self.processorDirectory == "default":
            # Default to fuzzer file folder
            self.processorDirectory = self.fuzzerFolder
        else:
            # Make sure fuzzer file path is prepended
            self.processorDirectory = os.path.join(self.fuzzerFolder, self.processorDirectory)

        #Create class director, which import/overrides processors as appropriate
        self.procDirector = ProcDirector(self.processorDirectory,args.prepped_fuzz,args.forceMsgProc,args.quiet)

        ########## Launch child monitor thread
        #  
        self.lock_condition = args.lock
        self.monitor = self.procDirector.getMonitor(self.host,\
                                                    self.fuzzerData.port,\
                                                    self.lock_condition)

        self.logger = None
        if len(args.logger):
            self.logger = Logger(args.logger)
            self.DUMPDIR = args.logger

            
        self.exceptionProcessor = self.procDirector.exceptionProcessor()
        self.messageProcessor = self.procDirector.messageProcessor()
        signal.signal(signal.SIGINT, self.sigint_handler)

        ########## Begin fuzzing
        self.i =  self.MIN_RUN_NUMBER
        self.failureCount = 0
        self.loop_len = len(self.SEED_LOOP) # if --loop

        if args.loop:
            self.seed = 0

        # sets up currentMessageToFuzz
        self.fuzzerData.currentMessageToFuzz = 0
        self.curr_seed_base = self.MIN_RUN_NUMBER 
        #round robin
        if args.rrobin:
            self.output("Fuzzing Packets: %s"%self.fuzzerData.messagesToFuzz)
            self.round_robin_iter_len = args.rrobin

        if args.harness:
            self.output("Fuzzing Packets: %s"%self.fuzzerData.messagesToFuzz)
            self.output("Starting harness_trace, if any!",ORANGE)
            self.monitor.start_harness_trace()



    # Takes a socket and outbound data packet (byteArray), sends it out.
    # If debug mode is enabled, we print out the raw bytes
    def sendPacket(self,connection, addr, outPacketData):
        if connection.type == socket.SOCK_STREAM:
            connection.send(outPacketData)
        else:
            connection.sendto(outPacketData,addr)

        if DEBUG_MODE:
            self.output("\tSent %d byte packet" % (len(outPacketData)))
            self.output("\tRaw Bytes: %s" % repr(Message.serializeByteArray(outPacketData)))


    def receivePacket(self,connection, addr, bytesToRead,msgNum):
        readBufSize = 4096
        if self.args.timeout:
            connection.settimeout(self.args.timeout)
        else:
            connection.settimeout(self.fuzzerData.receiveTimeout)

        if connection.type == socket.SOCK_STREAM or connection.type == socket.SOCK_DGRAM:
            response = bytearray(connection.recv(readBufSize))
        else:
            try:
                response = bytearray(connection.recvfrom(readBufSize))
            except:
                return
        
        
        if len(response) == 0:
            # If 0 bytes are recv'd, the server has closed the connection
            # per python documentation
            raise ConnectionClosedException("Server has closed the connection on msg:%d"%msgNum)
        if bytesToRead > readBufSize:
            # If we're trying to read > 4096, don't actually bother trying to guarantee we'll read 4096
            # Just keep reading in 4096 chunks until we should have read enough, and then return
            # whether or not it's as much data as expected
            i = readBufSize
            while i < bytesToRead:
                response += bytearray(connection.recv(readBufSize))
                i += readBufSize
                
        if DEBUG_MODE:
            self.output("\tReceived %d bytes" % (len(response)))
            self.output("\tReceived: %s" % repr(response))
        return response



    def makeConnector(self,host,port,messageProcessor,seed):

        if not self.socket_family:
            if match(r'^\d{1,3}(\.\d{1,3}){3}$',host):
                self.socket_family = socket.AF_INET
            elif match(r'([0-9A-Fa-f]{0,4})*(:[0-9A-Fa-f]{1,4})+',host) \
            and host.find("::") == host.rfind("::"):
                self.socket_family = socket.AF_INET6
            else:
                self.socket_family = socket.AF_UNIX

        if self.socket_family == socket.AF_UNIX:     
            addr = (host)
        else:
            addr = (host,self.fuzzerData.port)

        # Call messageprocessor preconnect callback if it exists
        try:
            self.messageProcessor.preConnect(seed, host, self.fuzzerData.port) 
        except AttributeError:
            pass

        # for TCP/UDP/RAW support
        if self.fuzzerData.proto == "tcp":
            connection = socket.socket(self.socket_family,socket.SOCK_STREAM)
            if self.fuzzerData.clientMode == True:
                #self.output("[*] Connecting to %s:%d"%addr)
                connection.connect(addr)
            else:
                self.output("[*] Binding to %s:%d"%addr,)
                connection.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
                connection.bind(addr)
                connection.listen(5) # should there be more? Variable?  
                
                
        elif self.fuzzerData.proto == "udp":
            connection = socket.socket(self.socket_family,socket.SOCK_DGRAM)
        # PROTO = dictionary of assorted L3 proto => proto number
        # e.g. "icmp" => 1
        elif self.fuzzerData.proto in PROTO:
            connection = socket.socket(self.socket_family,socket.SOCK_RAW,PROTO[self.fuzzerData.proto]) 
            if self.fuzzerData.proto != "raw":
                connection.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,0)
            addr = (host,0)
            try:
                connection = socket.socket(self.socket_family,socket.SOCK_RAW,PROTO[self.fuzzerData.proto]) 
            except Exception as e:
                self.output(e,YELLOW)
                self.output(e,"Unable to create raw socket, please verify that you have sudo access",RED)
                sys.exit(0)

        elif self.fuzzerData.proto == "L2raw":
            connection = socket.socket(socket.AF_PACKET,socket.SOCK_RAW,0x0300)
            #self.output("Creating Raw/Promisc socket")
            addr = (host,0)
        else:
            addr = (host,0)
            try:
                #test if it's a valid number 
                connection = socket.socket(self.socket_family,socket.SOCK_RAW,int(self.fuzzerData.proto)) 
                connection.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,0)
            except Exception as e:
                self.output(e,YELLOW)
                self.output(e,"Unable to create raw socket, please verify that you have sudo access",RED)
                sys.exit(0)

        if host == "255.255.255.255":
            connection.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        if self.logger:
            self.logger.resetForNewRun()

        return (connection,addr)
         


    # Perform a fuzz run.  Radamsa will be invoked after the
    # preprocessMessage() handler for the messages specified by
    # messagesToFuzz so that any changes made by the handler will be
    # reflected in the fuzzed messages.  If messagesToFuzz is None, no
    # fuzzing is performed.
    # If seed is -1, don't perform fuzzing (test run)
    def performRun(self,fuzzerData, host, messageProcessor, seed=-1):
        
        # socket of appropriate type, based of host/port 
        if not self.args.emulate:
            if not self.serverSocket or fuzzerData.clientMode: 
                # if we're in server Mode, don't create a new connection
                connection,addr = self.makeConnector(host,fuzzerData.port,messageProcessor,seed)   
        else:
            connection = None
        
        if not self.serverSocket and not fuzzerData.clientMode:
            # save server connection
            self.serverSocket = connection
            self.serverAddr = addr
        
        i = 0   

        if self.args.rrobin: 
            currentMessageToFuzz = fuzzerData.messagesToFuzz[fuzzerData.currentMessageToFuzz]
            for i in range(0, len(fuzzerData.messageCollection.messages)):
                try:
                    if i == int(currentMessageToFuzz): 
                        for j in range(0,len(fuzzerData.messageCollection[i].subcomponents)):
                            if float("%d.%d" % (i,j)) == currentMessageToFuzz: 
                                fuzzerData.messageCollection[i].subcomponents[j].isFuzzed = True
                            else:
                                fuzzerData.messageCollection[i].subcomponents[j].isFuzzed = False
                    else:
                        for j in range(0,len(fuzzerData.messageCollection[i].subcomponents)):
                            fuzzerData.messageCollection[i].subcomponents[j].isFuzzed = False

                except Exception as e:
                    self.output(str(e)) 

        # wait for the connection
        if not fuzzerData.clientMode:
            connection,addr = self.serverSocket.accept()
            # do a quick check to validate that it's actually our target? 
            '''
            if addr[0] != host:
                print "Unknown Connection received, ignoring! (%s,%d)"%addr  
                connection.close()
                return -1 
            '''

        for i in range(0, len(fuzzerData.messageCollection.messages)):
            self.output("") # Flush stdout buff
            message = fuzzerData.messageCollection[i]
            
            # Go ahead and revert any fuzzing or messageprocessor changes before proceeding
            message.resetAlteredMessage()

            # Primarily used for deciding how to handle preFuzz/preSend callbacks
            doesMessageHaveSubcomponents = len(message.subcomponents) > 1
            
            if message.direction == fuzzerData.fuzzDirection:                
                sub_fuzzed = False
                j = 0
                for subcomponent in message.subcomponents:
                    if subcomponent.isFuzzed:
                        sub_fuzzed = True
                    j+=1

                if sub_fuzzed:
                    if doesMessageHaveSubcomponents:
                        # Pre-fuzz on individual subcomponents first
                        for subcomponent in message.subcomponents:
                            if subcomponent.isFuzzed:
                            # Note: we WANT to fetch subcomponents every time on purpose
                                # This way, if user alters subcomponent[0], it's reflected when
                                # we call the function for subcomponent[1], etc
                                allSubcomponents = map(lambda subcomponent: subcomponent.getAlteredByteArray(), message.subcomponents)
                                prefuzz = messageProcessor.preFuzzSubcomponentProcess(subcomponent.getAlteredByteArray(), allSubcomponents)
                                subcomponent.setAlteredByteArray(prefuzz)
                    else:
                        # This is done for convenience
                        # legacy users / users not dealing with subcomponents can ignore the
                        # whole subcomponent thing by not having any, but
                        # lets us keep the backend straight
                        prefuzz = messageProcessor.preFuzzProcess(message.subcomponents[0].getAlteredByteArray())
                        message.subcomponents[0].isFuzzed = True
                        message.subcomponents[0].setAlteredByteArray(prefuzz)

                    # Skip fuzzing for seed == -1
                    if seed > -1:
                        # Now run the fuzzer for each fuzzed subcomponent
                        for subcomponent in message.subcomponents:
                            if subcomponent.isFuzzed:
                                if self.mutator == RADAMSA: 
                                    mutator = subprocess.Popen([self.mutator, "--seed", str(seed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                                else:
                                    mutator = subprocess.Popen([self.mutator, "--seed", str(seed)], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                                tmpByteArray = subcomponent.getAlteredByteArray()
                                (fuzzedByteArray, error_output) = mutator.communicate(input=tmpByteArray)
                                fuzzedByteArray = bytearray(fuzzedByteArray)
                                # skip/abort run..
                                if subcomponent.fixedSize > 0:
                                    fuzzedByteArray = fuzzedByteArray[0:subcomponent.fixedSize]

                                subcomponent.setAlteredByteArray(fuzzedByteArray)
                                self.saved_fuzzy_message = subcomponent.getAlteredByteArray()
                                    
                    # Fuzzing has now been done if this message is fuzzed
                    # Always call preSend() regardless for subcomponents if there are any
                    if doesMessageHaveSubcomponents:
                        for subcomponent in message.subcomponents:
                            # See preFuzz above - we ALWAYS regather this to catch any updates between
                            # callbacks from the user
                            allSubcomponents = map(lambda subcomponent: subcomponent.getAlteredByteArray(), message.subcomponents)
                            presend = messageProcessor.preSendSubcomponentProcess(subcomponent.getAlteredByteArray(), allSubcomponents)
                            subcomponent.setAlteredByteArray(presend)
        
                    if not doesMessageHaveSubcomponents:
                        self.saved_fuzzy_message = message.getAlteredMessage()
                    
                old_len = len(message.getOriginalMessage())
                new_len = len(message.getAlteredMessage()) 
                if old_len != new_len:
                    self.output("Message %s, seed: %d, old len: %d, new len %d" %(i,seed,old_len,new_len),CYAN)
                
                # Always let the user make any final modifications pre-send, fuzzed or not
                byteArrayToSend = messageProcessor.preSendProcess(message.getAlteredMessage())
                
                 

                # send Regardless if fuzzed or not
                if not self.args.emulate:
                    try:
                        self.sendPacket(connection, addr, byteArrayToSend)
                    except Exception as e:
                        message.resetAlteredMessage()


                message.resetAlteredMessage()

                if len(self.DUMPDIR) and (self.args.dumpraw or self.args.emulate):
                    msgnum = self.args.dumpraw or self.args.emulate
                    loc = os.path.join(self.logger._folderPath,"%d-outbound-seed-%d"%(i,msgnum))
                    with open(loc,"wb") as f:
                        f.write(repr(byteArrayToSend)[1:-1])

                if self.args.xploit:
                    msgnum = self.args.dumpraw or self.args.emulate or seed
                    #self.output("Boop: %d" % msgnum)
                    if msgnum == 0:
                        pocmsg = message.getOriginalMessage()
                    else:
                        pocmsg = byteArrayToSend

                    for i in range(0,len(pocmsg),self.POC_PACKET_COLS):
                        try:
                            # split up really long lines
                            self.poc_packet_cache.append(("outbound",pocmsg[i:i+self.POC_PACKET_COLS]))
                        except:
                            self.poc_packet_cache.append(("outbound",pocmsg[i:]))


            elif message.direction != fuzzerData.fuzzDirection: 
                messageByteArray = message.getAlteredMessage()
                if not self.args.emulate:
                    data = ""
                    try:
                        data = self.receivePacket(connection,addr,len(messageByteArray),i)
                    except Exception as e:
                        if "timed" in e:
                            connection.close()
                            raise 

                    if not data:
                        return 
                    #if data == messageByteArray:
                        #self.output("\tReceived expected response",GREEN)
                    self.messageProcessor.postReceiveProcess(data, messageByteArray, i)

                if len(self.DUMPDIR) and (self.args.dumpraw or self.args.emulate):
                    msgnum = self.args.dumpraw or self.args.emulate
                    loc = os.path.join(self.logger._folderPath,"%d-inbound-seed-%d"%(i,msgnum))
                    with open(loc,"wb") as f:
                        f.write(repr(str(message.getOriginalMessage()))[1:-1])

                if self.args.xploit:
                    msg = message.getOriginalMessage()
                    for i in range(0,len(msg),self.POC_PACKET_COLS):
                        try:
                            self.poc_packet_cache.append(("inbound",msg[i:i+self.POC_PACKET_COLS]))
                        except:
                            self.poc_packet_cache.append(("inbound",msg[i:]))

            i += 1
        
        try: 
            connection.close()
        except:
            pass

            
    def generate_poc(self,IP,filename=""): 
        if filename:
            fname = filename
        else:
            fname = self.args.xploit
        
        IP = self.args.target_host
        PORT = self.fuzzerData.port
        skeleton=os.path.abspath( os.path.join(__file__, "../util/skeleton_poc.py") )
        with open(skeleton,"r") as f:
            with open("%s"%fname,"wb") as e:
                # for readability
                #print self.poc_packet_cache
                poc_buffer = str(self.poc_packet_cache).replace(")), (", ")),\n(") 
                poc_buffer = poc_buffer.replace("[(","[\n(")
                poc_buffer = poc_buffer.replace(")]",")\n]")
                #self.output("Generate_POC params: %s %d %s"%(IP,PORT,str(poc_buffer))) 
                inp = f.read()
                e.write(inp%(str(IP),PORT,str(poc_buffer))) 
                self.poc_packet_cache = [] # clear it out, yo
                if not self.campaign:
                    self.output("[^_^] Generate_POC completed!: %s %s %d"%(fname,IP,PORT)) 
    
    
    # give a dumped fuzzer, get back a poc
    def generate_poc_from_fuzzer(self,fuzzer): 
        IP = self.args.target_host
        PORT = self.fuzzerData.port
        skeleton=os.path.abspath( os.path.join(__file__, "../util/skeleton_poc.py") )
        
        with open(skeleton,"r") as f:
            tmp_packet_cache = [] 
            for line in fuzzer.split("\n"):
                if line.startswith("outbound"):
                    pocmsg = line[line.find("'")+1:-1] 
                    if len(pocmsg):
                        tmp_packet_cache.append(("outbound",bytearray(pocmsg)))
                elif line.startswith("inbound"):
                    pocmsg = line[line.find("'")+1:-1] 
                    if len(pocmsg):
                        tmp_packet_cache.append(("inbound",bytearray(pocmsg)))
                
            # for readability
            #print self.poc_packet_cache
            poc_buffer = str(tmp_packet_cache).replace(")), ", ")),\n") 
            poc_buffer = poc_buffer.replace(")), (", ")),\n(") 
            poc_buffer = poc_buffer.replace("[(","[\n(")
            poc_buffer = poc_buffer.replace(")]",")\n]")
            poc_buffer = poc_buffer.replace("\\\\x","\\x")
            #self.output("Generate_POC params: %s %d %s"%(IP,PORT,str(poc_buffer))) 
            inp = f.read()
            return inp%(str(IP),PORT,str(poc_buffer)) 
         


    # Set up signal handler for CTRL+C and signals from child monitor thread
    # since this is the same signal, we use the monitor.crashEvent flag()
    # to differentiate between a CTRL+C and a interrupt_main() call from child 
    def sigint_handler(self,signal,idk=None):
        if not self.monitor.crashEvent.isSet():
            if self.campaign:
                try:
                    self.camp_sock.close()
                    self.ipc_sock.close()
                except:
                    pass
            # No event = quit
            # Quit on ctrl-c
            self.output("\nSIGINT received, stopping\n",RED)
            if signal > 0:
                sys.exit(0)
            else:
                return

    
    def fuzz(self):
        args = self.args
        fuzzerData = self.fuzzerData
        host = self.host
        messageProcessor = self.messageProcessor
        orig_timeout = -1

        #self.output("\n**Performing test run without fuzzing...",CYAN)

        self.output("[*] Entering main fuzzing loop (target: %s|%d)"%(host,fuzzerData.port),GREEN)
        if self.fuzzerData.clientMode == True:
            self.monitor.lockExecution() # lock till conditional is met
            self.output("[*] Target detected, fuzzing.",GREEN)
        else:
            self.output("[*] Waiting for incoming packets",CYAN) 
        
        #print "Fuzzing %d-%d" %(self.MIN_RUN_NUMBER,self.MAX_RUN_NUMBER)
        while True:
            i = self.i 
            if self.campaign:
                #self.output("[m.m] boop",CYAN)
                action = self.camp_sock.recv(4096) 
                #self.output("[m.m] doop %s"%repr(action),CYAN)
                if action[0:2] == "go": 
                    msg = float(fuzzerData.messagesToFuzz[fuzzerData.currentMessageToFuzz])
                    m,sm = str(msg).split(".")
                    resp = "%d,%s,%s"%(i-1,m,sm)
                    self.camp_sock.send(resp) # an ack of sorts

                if "delimdump" in action:
                    # dump the new .fuzzer to a string to send back to campaign
                    #self.output("Dumping current seed delim: %d"%(self.i-1))
                    new_fuzzer = deepcopy(self.fuzzerData)
                    self.output("saved fuzzy message: %s"%resp)
                    new_fuzzer.editCurrentlyFuzzedMessage(self.saved_fuzzy_message)
                    self.camp_sock.send(new_fuzzer.writeToFD(delim="\\n"))
                    action = ""
                    continue

                if "fulldump" in action:
                    # dump the new .fuzzer to a string to send back to campaign
                    #self.output("Dumping current seed full: %d"%(self.i-1))
                    new_fuzzer = deepcopy(self.fuzzerData)
                    new_fuzzer.editCurrentlyFuzzedMessage(self.saved_fuzzy_message)
                    self.output("saved fuzzy message: %s"%resp)
                    self.camp_sock.send(new_fuzzer.writeToFD(delim=""))
                    self.output("saved fuzzy message: %s"%resp)
                    action = ""
                    continue

                if action[0:3] == "len":
                    self.camp_sock.send("%s"%len(self.saved_fuzzy_message)) 

                if action[0:3] == "die":
                    self.sigint_handler(1)
                    break
                     
            lastMessageCollection = deepcopy(fuzzerData.messageCollection)
            wasCrashDetected = False

            if args.sleeptime > 0:
                #self.output("\n** Sleeping for %.3f seconds **" % args.sleeptime,BLUE)
                time.sleep(args.sleeptime)

            if args.rrobin: 
                if i % self.round_robin_iter_len == 0 and i > 0:
                    fuzzerData.rotateNextMessageToFuzz() 

                    if fuzzerData.currentMessageToFuzz == 0:
                        self.curr_seed_base += self.round_robin_iter_len

                    self.i = self.curr_seed_base 
                    i = self.i
            try:
                try:
                    if args.dumpraw or args.emulate:
                        tmp = 0
                        if args.dumpraw:
                            tmp_seed = args.dumpraw 
                        if args.emulate:
                            tmp_seed = args.emulate
                        self.output("\nPerforming single raw dump case: %d" % tmp_seed,CYAN)
                        self.performRun(fuzzerData, host, messageProcessor, seed=tmp_seed)  

                    elif self.loop_len: 
                        #self.output("\n***Fuzzing with seed %d, Message %s" % (self.SEED_LOOP[i%self.loop_len],fuzzerData.messagesToFuzz[fuzzerData.currentMessageToFuzz]),CYAN)
                        self.performRun(fuzzerData, host, messageProcessor, seed=self.SEED_LOOP[i%self.loop_len]) 

                    else:
                        #self.output("\n**Fuzzing with seed %d, Message %s" % (i,fuzzerData.messagesToFuzz[fuzzerData.currentMessageToFuzz]),CYAN)
                        status = self.performRun(fuzzerData, host, messageProcessor, seed=i) 
                        orig_timeout = -1
                        if status == -1:
                            continue 
                         
                except Exception as e:
                    self.output(str(e))
                    if self.monitor.crashEvent.isSet():
                        self.output("Crash event detected",LIME)
                        self.monitor.crashEvent.clear()
                        try:  #will error if monitor not enabled 
                            ip_port = self.monitor.lockExecution() # lock till conditional is met
                            fuzzerData.port = int(ip_port.split("|")[1])
                        except:
                            pass
                    
                    if e.__class__ in MessageProcessorExceptions.all:
                        # If it's a MessageProcessorException, assume the MP raised it during the run
                        # Otherwise, let the MP know about the exception
                        raise e
                    else:
                        self.exceptionProcessor.processException(e)
                        # Will not get here if processException raises another exception self.output("Exception ignored: %s" % (str(e)))
                
            except LogCrashException as e:
                if self.failureCount == 0:
                    self.output("Mutiny detected a crash",RED)

                self.failureCount = self.failureCount + 1
                wasCrashDetected = True

            except AbortCurrentRunException as e:
                # Give up on the run early, but continue to the next test
                # This means the run didn't produce anything meaningful according to the processor
                if str(e).lower().startswith("timed out"): 
                    if orig_timeout == -1:
                        orig_timeout = i
                        #self.output("Timeout Candidate: %d"%orig_timeout)

            except RetryCurrentRunException as e:
                # Same as AbortCurrentRun but retry the current test rather than skipping to next
                self.output("Retrying current run: %s" % (str(e)))
                # Slightly sketchy - a continue *should* just go to the top of the while without changing i
                continue
                
            except LogAndHaltException as e:
                self.output("Received LogAndHaltException, halting but not logging (quiet mode)",YELLOW)
                break 

            except LogSleepGoException as e:
                if i > self.MIN_RUN_NUMBER:
                    curr_time = datetime.datetime.now() 

                    crash_dump_dir = os.path.join(os.getcwd(),"autogen_pocs")
                    try:
                        os.mkdir(crash_dump_dir)
                    except:
                        #self.output("Unable to generate harness logs dir...")
                        pass 

                    crash_dump_file = os.path.join(os.getcwd(),"mutidumps.txt")
                     
                    if orig_timeout == -1:
                        orig_timeout = i+1
                    else:
                        i = orig_timeout   
        
                    crash_output = ""
                    if self.crash_client != None:
                        try:
                            while True:
                                try:
                                    tmp = cli_sock.recv(65535)  
                                    if tmp:
                                        crash_output+=tmp
                                    else:
                                        break
                                except socket.timeout:
                                    break
                            cli_sock.close() 
                            self.output("[^_^] Got crash output...%d bytes"%len(crash_output))
                        except:
                            pass 
                                            
                        
                            

                    self.output("[^_^] Potential crash@(%s) - Fuzzer: %s, Seed %d, Message %s \n"%(curr_time,self.fuzzerFilePath,self.i-1,\

                                                                                          fuzzerData.messagesToFuzz[fuzzerData.currentMessageToFuzz])) 
                    

                    with open(crash_dump_file,"a") as f:
                        f.write("**************************\n")
                        f.write("[^_^] Potential crash@(%s) - Fuzzer: %s, Seed %d, Message %s \n"%(curr_time,self.fuzzerFilePath,self.i-1,\
                                                                                              fuzzerData.messagesToFuzz[fuzzerData.currentMessageToFuzz])) 
                        if crash_output:
                            f.write(crash_output)
                       
                            new_fuzzer = deepcopy(self.fuzzerData)
                            new_fuzzer.editCurrentlyFuzzedMessage(self.saved_fuzzy_message)
                            poc = self.generate_poc_from_fuzzer(new_fuzzer.writeToFD(delim="")) 
                            f.write(poc)
                            crash_poc_file = os.path.join(crash_dump_dir,"%s_%d_%s.py"% (os.path.basename(self.fuzzerFilePath),i-1,\
                                                                                     fuzzerData.messagesToFuzz[fuzzerData.currentMessageToFuzz])) 
                            with open(crash_poc_file,"w") as f2:
                                f2.write(poc)
                    

                    try:
                        ip_port = self.monitor.lockExecution() # lock till conditional is met
                        fuzzerData.port = int(ip_port.split("|")[1])
                        orig_timeout = -1
                        #self.output("Resuming fuzzing! (Target:%s)"%(ip_port)) 
                    except Exception as e: #will error if monitor not enabled 
                        self.output(e)
                        pass
                else:
                    break

            except LogLastAndHaltException as e:
                self.output("Received LogLastAndHaltException, halting but not logging (quiet mode)",YELLOW)
                break
            
            except HaltException as e:
                self.output("Received HaltException halting",RED)
                break

            except KeyboardInterrupt:
                self.sigint_handler(1) 

            except Exception as e:
                self.output("Unhandled Exception: %s"%str(e))

            if wasCrashDetected:
                if self.failureCount < fuzzerData.failureThreshold:
                    #self.output("Failure %d of %d allowed for seed %d" % (self.failureCount, fuzzerData.failureThreshold, i),YELLOW)
                    #self.output("The test run didn't complete, continuing after %d seconds..." % (fuzzerData.failureTimeout))
                    time.sleep(fuzzerData.failureTimeout)
                else:
                    self.output("Failed %d times, moving to next test." % (self.failureCount))
                    self.failureCount = 0
                    self.i += 1
            else:
                self.i += 1

            # Stop if we have a maximum and have hit it
            if self.MAX_RUN_NUMBER >= 0 and self.i > self.MAX_RUN_NUMBER:
                self.output("Hit maximum")
                if args.harness:
                    self.monitor.stop_harness_trace()
                break

            if args.xploit:
                self.generate_poc(host) 

            if args.dumpraw or args.emulate:
                if args.harness:
                    self.monitor.stop_harness_trace()
                break

        #self.output("hit end of fuzz loop")


    def output(self,inp,color=None,comms_sock=None):
        inp = str(inp)
        if self.args.quiet:
            return

        buf = ""
        if color:
            buf=("%s%s%s" % (color,str(inp),CLEAR))
        else:
            buf=str(inp)

        if comms_sock:
            sock.send(buf) 
        else:
            rows = 0 # keep track of how many rows we've used.
            rows_left = 0
            if inp.startswith("Message"):
                self.fuzzer_messages.append(buf)
            else:
                if not buf:
                    return
                self.important_messages.append(buf)

            os.system('clear')
            
            # actually output the msgs.
            for i in range(0,len(self.banner_messages)):
                m = self.banner_messages[i]
                sys.__stdout__.write(m+"\n")
                rows+=1

            sys.__stdout__.write(("*"*48)+"\n")
            sys.__stdout__.flush()
            rows+=1

            rows+=6 # for fuzzer_messages
            
            for i in range(0,len(self.important_messages)):
                rows_left = (int(self.window_height)/2)-rows
                m = self.important_messages[i]
                sys.__stdout__.write(m+"\n")

                if i > rows_left:
                    self.important_messages = self.important_messages[-rows_left:]   
                    break 

            sys.__stdout__.write(("*"*48)+"\n")
            
            for i in range(0,len(self.fuzzer_messages)):
                m = self.fuzzer_messages[i]
                sys.__stdout__.write(m+"\n")
                if i >= 5: 
                    self.fuzzer_messages = self.fuzzer_messages[-5:]   
                    break

            sys.__stdout__.flush()
          

        try:
            self.logger.logSimple(inp)
        except AttributeError:
            pass

    

#######################################################
# End MutinyFuzzer Class
#######################################################

#colors
RED='\033[31m'
ORANGE='\033[91m'
GREEN='\033[92m'
LIME='\033[99m'
YELLOW='\033[93m'
BLUE='\033[94m'
PURPLE='\033[95m'
CYAN='\033[96m'
CLEAR='\033[00m'


def output(self,inp,color=None,comms_sock=None):
        buf = ""
        if color:
            buf+=("%s%s%s\n" % (color,str(inp),CLEAR))
        else:
            buf+=str(inp)+"\n"

        if comms_sock:
            sock.send(buf) 
        else:
            sys.__stdout__.write(buf)
            sys.__stdout__.flush()


#----------------------------------------------------
# Set self.MIN_RUN_NUMBER and self.MAX_RUN_NUMBER when provided
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


def get_mutiny_with_args(prog_args):

    desc =  "======== The Mutiny Fuzzing Framework ==========" 
    epi = "==" * 24 + '\n'

    parser = argparse.ArgumentParser(description=desc,epilog=epi)
    parser.add_argument("prepped_fuzz", help="Path to file.fuzzer")
    parser.add_argument("-L","--logger", help="Create a log dir/start logging",default="")
    parser.add_argument("-i","--target_host", help="Target host to fuzz",default="127.0.0.1")
    parser.add_argument("-s","--sleeptime",help="Time to sleep between fuzz cases (float)",type=float,default=0)
    parser.add_argument("-p","--port",help="Override the port included in the .fuzzer file",type=int,default=0)
    # since -r is already taken -_-. Need a better name for this
    parser.add_argument("-R","--rrobin",help="Round robin rotate, amount of iter per messageToFuzz",type=int)
    parser.add_argument("-t","--timeout",help="Time to wait when recv(). Overrides .fuzzer",type=float,default=2)
    parser.add_argument("-m","--msgtofuzz",help="Fuzz specific msgs. [x|x-y|x,y,z-Q] Overrides .fuzzer")

    seed_constraint = parser.add_mutually_exclusive_group()
    seed_constraint.add_argument("-r", "--range", help="Run only the specified cases. Acceptable arg formats: [ X | X- | X-Y ], for integers X,Y") 
    seed_constraint.add_argument("-l", "--loop", help="Loop/repeat the given finite number range. Acceptible arg format: [ X | X-Y | X,Y,Z-Q,R | ...]")
    seed_constraint.add_argument("-d", "--dumpraw", help="Test single seed, all packets saved seperately",type=int)
    seed_constraint.add_argument("-e", "--emulate", help="Same as '--dumpraw', but no packets sent",type=int)
    parser.add_argument("-M","--mutator",help="Specify a custom mutator binary. By default use Radamsa",default=RADAMSA)
    parser.add_argument("-x","--xploit",help="generate a POC or the given seed. Requires -d or -e")
    parser.add_argument("-H","--harness",help="trigger target harness start/stop defined in monitor class")
    parser.add_argument("-C","--campaign",help="Fuzzing Campaign mode, you probably don't wanna use this, refer to campaign.py for further details, arg==port",type=int)
    parser.add_argument("-k","--lock",help="Determines when to stop/start fuzzing. More info in mutiny_classes/monitor.py.",default="remote_tcp_open")
    parser.add_argument("-F", "--forceMsgProc", help="Use the default MSG Processor, not those found in fuzzers (good for campaign)",action="store_true")
    parser.add_argument("-c","--crashes",help="<Ip:port> Bind to ip/port and listen for crashes from fuzzing harness")
    

    verbosity = parser.add_mutually_exclusive_group()
    verbosity.add_argument("-q", "--quiet", help="Don't log the self.outputs",action="store_true")

    args = parser.parse_args(prog_args)
    try:
        fuzzer = MutinyFuzzer(args)
    except:
        raise
    return fuzzer

if __name__ == "__main__":
    # Usage case
    if len(sys.argv) < 2:
        sys.argv.append('-h')

    #TODO: add description/license/ascii art print out??

    fuzzer = get_mutiny_with_args(sys.argv[1:])
    try:
        fuzzer.fuzz()
    except KeyboardInterrupt:
        fuzzer.sigint_handler(1) 
