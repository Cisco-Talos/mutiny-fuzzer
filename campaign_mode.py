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
HARNESS_PORT = 60000

SOCKTIMEOUT = .01 
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

FUZZERTIMEOUT = .1
try:
    FUZZERTIMEOUT = float(sys.argv[sys.argv.index("--timeout")+1])
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
                data = f.read()
                if "outbound fuzz" not in data and "more fuzz" not in data:
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
        
        time.sleep(2)
        if fuzzer_queue.empty(): 
            print "[?.x] Couldn't find any .fuzzer files in %s what do?" % fuzzer_dir 
            return

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
                                                     done_switch,
                                                     logs))
    harness_thread.start()
    time.sleep(1)

    # wait here, don't care, about doing anything else until we
    # can talk with the mutiny instance.
    while True:
        try:
            control_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
            control_sock.connect((IP,PORT)) 
            break
        except KeyboardInterrupt:
            done_switch.set()
            time.sleep(1)
            print "[^_^] Campaign mode exited! Thanks for visiting!"
            sys.exit()
        except:
            time.sleep(1)
            #print "Could not connect to mutiny :("
    
    control_sock.send("go")            
    dumped_fuzzer = ""
    crash = ""
    last_seed = ""

    try:
        while True:
            logs.flush()
            
            if done_switch.is_set():
                try:
                    control_sock.send("die")
                except:
                    pass
                break

            # recv current seed
            resp = get_bytes(control_sock)
            if len(resp):
                last_seed = resp

            try:
                # got a crash from harness_socket
                crash = crash_queue.get_nowait()
            except Empty:
                crash = ""

            if len(crash):
                # is there a delay on fulldump/delimdump? :/
                control_sock.send("fulldump")
                while len(dumped_fuzzer) < 0x20:
                    dumped_fuzzer = get_bytes(control_sock) 
                    time.sleep(.1)

                print "[^_^] got fuzzer! %d bytes"%len(dumped_fuzzer)

                # add to queue
                seed,msg,submsg = last_seed.split(",")
                tmp = ""
                tmp+="\n*******************\n" 
                tmp+="Seed: %s, Msg:%s.%s\n"%(seed,msg,submsg)
                tmp+="\n*******************\n" 
                tmp+="******CRASH*******\n" 
                tmp+=crash
                tmp+="******FUZZER*******\n" 
                tmp+=dumped_fuzzer
                tmp+="*******************\n"
                logs.write(tmp)
                logs.flush()

                with open("crashes/%s"%datetime.datetime.now(),"wb") as f:
                    f.write(tmp) 
                time.sleep(process_respawn_time)
                dumped_fuzzer = ""
                crash = ""

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
        done_switch.set()
        print "[^_^] Exiting!"
        sys.exit() 

def get_bytes(sock,timeout=SOCKTIMEOUT):
    ret = ""
    sock.settimeout(timeout)
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


def crash_listener(crash_queue,done_switch,logger):
    harness_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    harness_socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    try:
        harness_socket.bind((HARNESS_IP,HARNESS_PORT))
    except:
        print "Could not bind crash listener...."
        logger.write("[x.x] Could not bind crash listener....")
        done_switch.set()
        return

    harness_socket.listen(3)
    
    cli_sock,cli_addr = harness_socket.accept() 
    while True:
        try:
            cli_resp = get_bytes(cli_sock,1)
            if len(cli_resp):
                logger.write("crash_list got %d bytes"%len(cli_resp))
            crash_queue.put(cli_resp)
        except socket.timeout:
            pass
        except Exception as e:
            logger.write(str(e))
            sys.__stdout__.write(str(e))
            sys.__stdout__.flush()
            cli_sock,cli_addr = harness_socket.accept() 
            logger.flush()

        if done_switch.is_set():
            break

def get_controller_fuzzer():
    #! TODO     
    return None


def launch_fuzzer(fuzzer,control_port,amt_per_fuzzer,timeout,done_switch):
    
    args = [fuzzer,
            "--campaign",str(control_port),
            "-r","%d-"%SKIP_TO,
            "-R","%d"%(amt_per_fuzzer/100),
            "-t",str(timeout), 
            "-i",target_ip,
            "-F"
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
                    "-R","%d"%(amt_per_fuzzer/100),
                    "-t",str(timeout), 
                    "-i",target_ip,
                    "-F"
            ]
            
            if target_port:
                args.append("--port")
                args.append(str(target_port))

            msg = "" 
            msg += "-------------------------------\n"
            msg += "Starting on %s (%d-%d) @ %s\n" %(fuzzer,lowerbound,\
                                                          upperbound,datetime.datetime.now())
            msg+="#!"
            msg+=str(args)
            msg+="-------------------------------\n"
            logger.write(msg)
            
            fuzzy = get_mutiny_with_args(args)
            fuzzy.fuzz()
            fuzzy.sigint_handler(-1)
        except KeyboardInterrupt:
            break
        
        except Exception as e:
            print e
            logger.write(str(e))
            logger.flush()
    
        # Move over to processed_fuzzer dir 
        # if we're only doing campaign, I don't fucking care.
        # os.rename(fuzzer,os.path.join(processed_dir,os.path.basename(fuzzer))) 
        if done_switch.is_set():
            break

    done_switch.set()
    print "[^_^] DONE!"


if __name__ == "__main__":
    try:
        os.mkdir("crashes")
    except:
        pass
    with open("fuzzer_log.txt",'a') as logger:
        main(logger)
