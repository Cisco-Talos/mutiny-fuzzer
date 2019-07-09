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
# This is a sample campaign, I tend to copy one for each given target 
# that I hit. <(^_^)>
# Essentially an encapsulating script for the Mutiny class, it will set up
# communications with the fuzzer, telling it 'go'/'dump' and such, while
# also listening from any input from the corresponding harness on the target
# (if any). 

import os
import sys
import time
import socket
import os.path
import datetime
import multiprocessing

from Queue import Empty
from mutiny import *

# used for mutiny<->campaign comms
IP = "127.0.0.1"
PORT = 61600

HARNESS_IP = "0.0.0.0"
HARNESS_PORT = 6969

SOCKTIMEOUT = .01 
FUZZERTIMEOUT = .02
CASES_PER_FUZZER = 40000

logger = None

process_respawn_time = 1


if len(sys.argv) < 3:
    print "[x.x] Usage: %s <fuzzer dir/file> <target_IP>" % sys.argv[0]
    sys.exit()

fuzzer_dir = None
fuzzer_file = None
if os.path.isdir(sys.argv[1]):
    fuzzer_dir = sys.argv[1]
elif os.path.isfile(sys.argv[1]):
    fuzzer_file = sys.argv[1]
else:
    print "[x.x] Couldn't find fuzzer file/dir %s" % sys.argv[0]   
    sys.exit()

target_ip = sys.argv[2]

try:
    target_port = int(sys.argv[sys.argv.index("--port")+1])
except Exception as e:
    target_port = ""

SKIP_TO = 0
try:
    SKIP_TO = int(sys.argv[sys.argv.index("--seed")+1])
except Exception as e:
    pass

#! Distributed fuzzing
#! add flag for fuzzer file source (https get checks on queue)
#! each campaign can just check a different url for .fuzzers.
#! for example --controller 10.10.10.1/fuzzer2 , fuzzer3....  

#! also can have --threads 4 to multithread. 
#! .fuzzers gotten from campaign controller will be 
#! distributed to the thread via the fuzzer_queue 

#! how to check for core count?


def main(logs):

    done_switch = multiprocessing.Event()
    crash_queue = multiprocessing.Queue()
    thread_count = 1

    # single .fuzzer mode
    if fuzzer_file:
        launch_thread = multiprocessing.Process(target = launch_fuzzer,
                                                args=(fuzzer_file,
                                                      PORT,
                                                      CASES_PER_FUZZER,
                                                      FUZZERTIMEOUT,
                                                      done_switch))
    # fuzzer corpus mode.
    elif fuzzer_dir:
        fuzzer_queue = multiprocessing.Queue()

        # prevent's dups from entering the fuzzer_queue
        append_lock = multiprocessing.Lock()

        print "[^_^] Reading in fuzzers from %s" % fuzzer_dir
        fuzzer_list = os.listdir(fuzzer_dir)
        '''
        try:
            # we do this to start fuzzing right away.
            fuzzer_list = fuzzer_list[0:10]
        except Exception as e:
            print e
            pass
        '''
         
        for f in fuzzer_list: 
            fname = os.path.join(fuzzer_dir,f)
            if os.path.isdir(fname):
                continue

            with open(fname,"r") as f:
                if "outbound fuzz" not in f.read():
                    continue
            
            fuzzer_queue.put(fname)
            print "[>_>] adding %s" % fname
            #time.sleep(1) # takes time to add to queue?!?
        
        # where completed fuzzers go.
        processed_dir = os.path.join(fuzzer_dir,"processed_fuzzers")
        try:
            os.mkdir(processed_dir)
        except:
            pass
        
        while fuzzer_queue.empty(): 
            print "[?.x] Couldn't find any .fuzzer files in %s what do?" % fuzzer_dir 
            sys.exit()

        #! multithread will requeire a harness thread and control_sock per
        launch_thread = multiprocessing.Process(target = launch_corpus,
                                                args=(fuzzer_dir,
                                                      append_lock,
                                                      fuzzer_queue,
                                                      PORT,
                                                      CASES_PER_FUZZER,
                                                      FUZZERTIMEOUT,
                                                      done_switch))


    launch_thread.daemon=True
    launch_thread.start()

    harness_thread = multiprocessing.Process(target = crash_listener,
                                             args = (crash_queue,
                                                     done_switch))
    harness_thread.start()
    time.sleep(1)

    # wait here, don't care, about doing anything else until we
    # can talk with the mutiny instance.
    while True:
        try:
            control_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
            control_sock.connect((IP,PORT)) 
        except KeyboardInterrupt:
            done_switch.set()
            time.sleep(1)
            print "[^_^] Campaign mode exited! Thanks for visiting!"
            sys.exit()
        except:
            time.sleep(1)
            #print "Could not connect to mutiny :("
    
    
    control_sock.send("go")            
    try:
        print "boop"
        while True:
            if done_switch.is_set():
                try:
                    control_sock.send("die")
                except:
                    pass
                break

            # recv current seed
            resp = get_bytes(control_sock)
             
            # we depend on the harnesses to only send data when there is a crash
            if len(resp):
                try:
                    # got a crash from harness_socket
                    crash = crash_queue.get_nowait()
                    if len(crash):
                        logs.write("resp:%s" % str(crash))
                        control_sock.send("dump")
                        dumped_fuzzer = get_bytes(control_sock) 

                        # in case there was extra data
                        if len(dumped_fuzzer) < 20:
                            dumped_fuzzer = get_bytes(control_sock) 

                        # add to queue
                        logs.write("\n*******************\n") 
                        logs.write("Seed: " + str(resp) + "\n")
                        
                        logs.write("\n*******************\n") 
                        logs.write("******CRASH*******\n") 
                        logs.write(crash)
                        logs.write("*******************\n") 
                        logs.write(dumped_fuzzer)
                        logs.write("*******************\n") 
                        logs.flush()
                        time.sleep(process_respawn_time)
                except Exception as e:
                    print e
                    pass

            try:
                control_sock.send("go")
            except:
                try:
                    print "[^_^] Swapping .fuzzer files"
                    time.sleep(2)
                    control_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
                    control_sock.connect((IP,PORT)) 
                    control_sock.send("go")
                except Exception as e:
                    print e
                    print "[;_;] we ded"
                    sys.exit()
    
    except KeyboardInterrupt:
        sys.exit() 

def get_bytes(sock):
    ret = ""
    sock.settimeout(SOCKTIMEOUT)
    try:
        while True:
            tmp = sock.recv(65535)
            if len(tmp):
                ret+=tmp
            else:
                break
    except Exception as e:
        pass

    return ret


def crash_listener(crash_queue,done_switch):
    harness_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    harness_socket.bind((HARNESS_IP,HARNESS_PORT))
    harness_socket.listen(3)
    
    while True:
        try:
            cli_sock,cli_addr = harness_socket.accept() 
            cli_resp = get_bytes(cli_sock)
            crash_queue.put(cli_resp)
            cli_sock.close()
        except socket.timeout:
            pass
        except Exception as e:
            print e

        if done_switch.is_set():
            break

def get_controller_fuzzer():
    #! TODO     
    return None


def launch_fuzzer(fuzzer,control_port,amt_per_fuzzer,timeout,done_switch):
    
    args = [fuzzer,
            "--campaign",str(control_port),
            "-r","%d-"%SKIP_TO
            "-R","%d"%(amt_per_fuzzer/100),
            "-t",str(timeout), 
            "-i",target_ip
    ]

    fuzzy = get_mutiny_with_args(args)
    fuzzy.fuzz()


    done_switch.set()


def launch_corpus(fuzzer_dir,append_lock,fuzzer_queue,control_port,amt_per_fuzzer,timeout,done_switch):


    lowerbound=SKIP_TO
    upperbound=lowerbound + amt_per_fuzzer
    
    repeat_counter = 0

    processed_dir = os.path.join(fuzzer_dir,"processed_fuzzers")

    while True:
        # check for .fuzzer files in controller
        if fuzzer_queue.empty():    
            if append_lock.acquire(block=True,timeout=4):
                new_fuzzer_list = os.listdir(fuzzer_dir)
                new_fuzzer_list.remove("processed_fuzzers") # 
                for f in new_fuzzer_list:
                    fuzzer_queue.put(os.path.join(fuzzer_dir,f)) 
                append_lock.release()
            
        # if still empty, check controller 
        if fuzzer_queue.empty():
            tmp = get_controller_fuzzer() 
            if tmp:
                fuzzer_name,fuzzer_contents = tmp 
                fuzzer_name = os.path.join(fuzzer_dir,fuzzer_name)
                with open(fuzzer_name,"w") as f:
                    f.write(fuzzer_contents)
            
        # if still empty, keep fuzzing with same fuzzer
        if not fuzzer_queue.empty():
            fuzzer = fuzzer_queue.get()
            repeat_counter = 0
        else:
            repeat_counter += 1
            
            #processed = os.path.join(processed_dir,os.path.basename(fuzzer))
            #os.rename(processed,fuzzer) 

        lowerbound = (amt_per_fuzzer * repeat_counter) + SKIP_TO 
        upperbound = (amt_per_fuzzer * (repeat_counter+1))  + SKIP_TO

        try:
            args = [fuzzer,
                    "--campaign",str(control_port),
                    "-r","%d-%d"%(lowerbound,upperbound),
                    #! add this via cmdline...
                    #"-R","%d"%(amt_per_fuzzer/100),
                    "-t",str(timeout), 
                    "-i",target_ip,
                    "-f"
            ]
            
            if target_port:
                args.append("--port")
                args.append(str(target_port))
            
            logger.write("-------------------------------\n")
            logger.write("Starting on %s (%d-%d) @ %s\n" %(fuzzer,lowerbound,\
                                                          upperbound,datetime.datetime.now()))
            logger.write("#!")
            logger.write(str(args))
            logger.write("-------------------------------\n")
            logger.flush()
            
            fuzzy = get_mutiny_with_args(args)
            fuzzy.fuzz()
            fuzzy.sigint_handler(-1)

        except Exception as e:
            print e
            logger.write(str(e))
            logger.flush()
    
        # Move over to processed_fuzzer dir 
        # if we're only doing campaign, I don't fucking care.
        # os.rename(fuzzer,os.path.join(processed_dir,os.path.basename(fuzzer))) 

    done_switch.set()
    print "[^_^] DONE!"


if __name__ == "__main__":
    with open("fuzzer_log.txt",'a') as logger:
        main(logger)
