#!/bin/python
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
import queue
import socket
import os.path
import multiprocessing

from mutiny import *

IP = "127.0.0.1"
PORT = 61600

HARNESS_IP = "0.0.0.0"
HARNESS_PORT = 6969

TIMEOUT = .01 
FUZZERTIMEOUT = .5
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


def main(logs):

    done_switch = multiprocessing.Event()
    crash_queue = multiprocessing.Queue()

    if fuzzer_file:
        launch_thread = multiprocessing.Process(target = launch_fuzzer,
                                                args=(fuzzer_file,
                                                      PORT,
                                                      10000,
                                                      FUZZERTIMEOUT,
                                                      done_switch))
    elif fuzzer_dir:
        launch_thread = multiprocessing.Process(target = launch_corpus,
                                                args=(fuzzer_dir,
                                                      PORT,
                                                      100,
                                                      FUZZERTIMEOUT,
                                                      done_switch))
    launch_thread.daemon=True
    launch_thread.start()


    harness_thread = multiprocessing.Process(target = crash_listener,
                                             args = (crash_queue,
                                                     done_switch))
    harness_thread.start()


    time.sleep(1)
    try:
        control_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
        control_sock.connect((IP,PORT)) 
    except:
        print "[;_;] we ded"
        sys.exit()

    control_sock.send("go")            
    try:
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
    sock.settimeout(TIMEOUT)
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


def launch_fuzzer(fuzzer,control_port,amt_per_fuzzer,timeout,done_switch):
    
    args = [fuzzer,
            "--campaign",str(control_port),
            "-r","0-%d"%amt_per_fuzzer,   
            "-R","%d"%(amt_per_fuzzer/100),
            "-t",str(timeout) 
    ]

    fuzzy = get_mutiny_with_args(args)
    fuzzy.fuzz()


    done_switch.set()


def launch_corpus(fuzzer_dir,control_port,amt_per_fuzzer,timeout,done_switch):

    lowerbound=0
    upperbound=amt_per_fuzzer

    fuzzer_list = os.listdir(fuzzer_dir)
    if len(fuzzer_list) < 0:
        print "[?.x] Couldn't find any .fuzzer files... what do?"    
        print fuzzer_queue
        sys.exit()

    for fuzzer in fuzzer_list:
        try:
            if fuzzer[-7:] == ".fuzzer": 
                args = [os.path.join(fuzzer_dir,fuzzer),
                        "--campaign",str(control_port),
                        "-r","%d-%d"%(lowerbound,upperbound),
                        "-t",str(timeout), 
                        "-i",target_ip
                ]
                
                logger.write("-------------------------------\n")
                logger.write("Starting on %s (%d-%d)\n" %(fuzzer,lowerbound,upperbound))
                logger.write("#!")
                logger.write(str(args))
                logger.write("-------------------------------\n")
                logger.flush()
                
                fuzzy = get_mutiny_with_args(args)
                fuzzy.fuzz()
                fuzzy.sigint_handler(-1)

        except Exception as e:
            logger.write(str(e))
            logger.flush()
    
    done_switch.set()
    print "[^_^] DONE!"


if __name__ == "__main__":
    with open("fuzzer_log.txt",'a') as logger:
        main(logger)
