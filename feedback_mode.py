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
# Use in conjunction with Gluttony Feedback. 
import os
import sys
import time
import Queue
import socket
import struct
import os.path
import datetime
import traceback
import multiprocessing

from mutiny import *

#TODO: register coverage?

# used for mutiny campaign socket. 
IP = "127.0.0.1"
CAMPAIGN_PORT = 61602

# used for feedback direction exclusively.
FEEDBACK_IP = "0.0.0.0"
FEEDBACK_PORT = 61601

# Used for minimization
MINIMIZE_IP = "0.0.0.0"
MINIMIZE_PORT = 61603

SOCKTIMEOUT = .01 
FUZZERTIMEOUT = .1

logger = None

RED='\033[31m'
ORANGE='\033[91m'
GREEN='\033[92m'
LIME='\033[99m'
YELLOW='\033[93m'
BLUE='\033[94m'
PURPLE='\033[95m'
CYAN='\033[96m'
CLEAR='\033[00m'
color_test = ['\033[31m','\033[91m','\033[92m','\033[99m','\033[93m','\033[94m','\033[95m','\033[96m','\033[00m']

#// ~~~~~~ Start outbound socket message definitions and utilities ~~~~~~~~ 
# <byte opcode> <uint_32t msg_len> <msg (if any)>
FUZZ_CASE            = "\x03\x00\x00\x00\x00"
FUZZ_CASE_DONE       = "\x04\x00\x00\x00\x00" 
TRACE_DONE           = "\x05\x00\x00\x00\x00" 
HEARTBEAT            = "\x0F\x00\x00\x00\x00"

#// ~~~~~~~ Start outbound message definitions and utilities ~~~~~~~
# <byte opcode> <uint_32t msg_len> <msg (if any)>
opcode_dict = {
    0x10:"save_queue",  #\x10 
    0x11:"pause",       #\x11
    0x12:"resume",      #\x12
    0x18:"mini_init",   #\x18
    0x19:"mini_result", #\x19
    0x1a:"mini_ready",  #\x1A
    0x1F:"save_crash",  #\x1F
    0xF0:"",
}


# msgs with variable data
# msgs with variable data len

if len(sys.argv) < 3:
    print "[x.x] Usage: %s <fuzzer dir/file> <target_IP> <mutiny arguments>" % sys.argv[0]
    sys.exit()

fuzzer_dir = None
fuzzer_file = None
if os.path.isdir(sys.argv[1]):
    fuzzer_dir = sys.argv[1]
elif os.path.isfile(sys.argv[1]):
    fuzzer_dir = "%s_%s"%(sys.argv[1],"corpus")
    try:
        os.mkdir(fuzzer_dir)
    except:
        pass
else:
    print "[x.x] Couldn't find fuzzer file/dir %s" % sys.argv[0]   
    sys.exit()

crash_dir = os.path.join(fuzzer_dir,"crashes")
queue_dir = os.path.join(fuzzer_dir,"queue")
processed_dir = os.path.join(fuzzer_dir,"processed")
# create queue/crash folders
try:
    os.mkdir(crash_dir)
    os.mkdir(processed_dir)
    os.mkdir(queue_dir)
except Exception as e:
    if "File exists" not in e:
        print e
        sys.exit()
    pass 

target_ip = sys.argv[2]

instance_count = 1  
try:
    try:
        ind = sys.argv.index("--threads")
        instance_count = int(sys.argv[ind+1])
        sys.argv = sys.argv[:ind] + sys.argv[ind+2:]
    except Exception as e:
        pass

    mutiny_args = sys.argv[3:]
except:
    pass



def main(logs):
    global SOCKTIMEOUT
    

    kill_switch = multiprocessing.Event()
    #outbound_queue = multiprocessing.Queue()
    print_queue = multiprocessing.Queue()
    
        
    
    inbound_queue_list = []
    fuzz_flag_list = []

    if instance_count > 0:
        output("[^_^] threaded mode! %d threads" % instance_count,"fuzzer",print_queue)

    for i in range(0,instance_count):
        inbound_queue_list.append(multiprocessing.Queue())
        fuzz_flag_list.append(multiprocessing.Event())
    
    print_thread = multiprocessing.Process(target = output_thread,
                                           args=(print_queue,
                                                 fuzz_flag_list, 
                                                 kill_switch,
                                                 instance_count)) 
    print_thread.start()

    if not fuzzer_dir:
        print "[x-x] Feedback_mode.py could not find fuzzer dir, exiting!"
        sys.exit()
    
    output("[^_^] Reading in fuzzers from %s" % fuzzer_dir,"fuzzer",print_queue)

    fuzzer_queue = multiprocessing.Queue()
    # pause/resume fuzzing
    # prevent's dups from entering the fuzzer_queue
    append_lock = multiprocessing.Lock()

    
    '''
    if len(file_list) > 10:
        # just to get started fster, rest will add later 
        file_list = file_list[0:9]     
    '''
    # first check to see if we already have a queue going
    fuzzer_count = 0
    processed_count = 0
    new_count = 0
    
    unfuzzed_list = []
    queue_list = os.listdir(queue_dir)
    if len(queue_list) > 0: # use queue_list instead.
        #output("Requeueue %s!"%(str(queue_list)),"fuzzer",print_queue)
        for f in queue_list:
            if f.endswith(".swp") or f.endswith(".swo"):
                continue 
    
            if f.endswith(".py") or f.endswith(".pyc"):
                continue

            #output("%s"%f,"fuzzer",print_queue)
            queued_file = os.path.join(queue_dir,f)
            if os.path.isfile(queued_file):
                #output("Loading %s!"%(queued_file),"fuzzer",print_queue)
                fuzzer_queue.put(queued_file)
                fuzzer_count+=1
                unfuzzed_list.append(queued_file)

    file_list = os.listdir(fuzzer_dir)
    #output("[!.!]%s"%file_list,"fuzzer",print_queue)
    
    for f in file_list:
        fuzzer_file = os.path.join(fuzzer_dir,f)
        if f.endswith(".swp") or f.endswith(".swo"):
            continue 

        if f.endswith(".py") or f.endswith(".pyc"):
            continue

        #if ".fuzzer" in f:
        if os.path.isfile(fuzzer_file):
            queued_file = os.path.join(fuzzer_dir,"queue",f)

            output("Queueing to %s!"%(queued_file),"fuzzer",print_queue)

            with open(queued_file,"w") as d: 
                with open(fuzzer_file,"r") as s:
                    # minor sanity test
                    tmp_buf = s.read()
                    if "fuzz" not in tmp_buf:
                        continue 
                    d.write(tmp_buf)
            os.remove(fuzzer_file)
            fuzzer_queue.put(queued_file)
            fuzzer_count+=1
            unfuzzed_list.append(queued_file)

    curr_seed = 0x0
    curr_msg = 0x0
    curr_submsg = 0x0
    crash_count = 0

    try:
        for i in range(0,instance_count):
            update_feedback_stats(crash_count,fuzzer_count,new_count,print_queue,i)
    except:
        oops()
    time.sleep(1)

    while fuzzer_queue.empty(): 
        output("[?.x] Couldn't find any .fuzzer files in %s what do?" % fuzzer_dir,"fuzzer",print_queue) 
        kill_switch.set()
        sys.exit()

    output("[!.!] Done loading corpus!","fuzzer",print_queue)
    #! multithread will requeire a harness thread and mutiny_control_sock per

    corpus_threads = []
    thread_list = [print_thread] 

    # also include processed fuzzers...
    for processed in os.listdir(processed_dir):
        filename = os.path.join(processed_dir,processed)
        unfuzzed_list.append(filename)

    for thread_num in range(0,instance_count):
        launch_thread = multiprocessing.Process(target = launch_corpus,
                                                args = (fuzzer_dir,
                                                       append_lock,
                                                       fuzzer_queue,
                                                       kill_switch,
                                                       fuzz_flag_list[thread_num],
                                                       mutiny_args[:],
                                                       print_queue,
                                                       unfuzzed_list[:], 
                                                       thread_num))

        launch_thread.name="launch_corpus-%d"%thread_num
        corpus_threads.append(launch_thread)
        thread_list.append(launch_thread)
        launch_thread.daemon=True
        launch_thread.start()
        
    if "--skip-unfuzzed" in mutiny_args:
        mutiny_args.remove("--skip-unfuzzed")


    output("[!.!] Done Spawning fuzzer thread!","fuzzer",print_queue)
    harness_threads = []

    for thread_num in range(0,instance_count):
        harness_thread = multiprocessing.Process(target = feedback_listener,
                                                   args = (inbound_queue_list[thread_num], 
                                                          kill_switch,
                                                          fuzz_flag_list[thread_num],
                                                          print_queue,
                                                          thread_num))

        harness_thread.name = "feedback_listener-%d"%thread_num
        harness_threads.append(harness_thread)
        thread_list.append(harness_thread)
        harness_threads[-1].start()

        output("[!.!] Block till feedback ready!","fuzzer",print_queue,thread_num,YELLOW)

    # don't need corpus 'minimizer' since we actually have real minimization support now.
    #corpus_minimizer_thread = multiprocessing.Process(target = corpus_minimizer,
    #                                                 args = (fuzzer_dir,
    #                                                         kill_switch,
    #                                                         print_queue))
    #corpus_minimizer_thread.start()
    #output("[!.!] Done Spawning minimizer thread!","fuzzer",print_queue)

    for thread in range(0,instance_count):
        ret = block_till_feedback_ready(inbound_queue_list[thread],kill_switch)
    
        if ret == -1:
            #sys.__stdout__.write(YELLOW + "[!.!] Ctrl+C => Entering Cleanup!\n" + CLEAR)
            #sys.__stdout__.flush()
            # cleanup queue 
            while not inbound_queue_list[thread].empty():
                inbound_queue_list[thread].get()
            '''
            while not outbound_queue.empty():
                outbound_queue.get()
            '''
            while not print_queue.empty():
                print_queue.get()
            while not fuzzer_queue.empty():
                fuzzer_queue.get()

            for t in thread_list:
                #sys.__stdout__.write("\n[x.x] Waiting on t %s\n"%str(t))
                #sys.__stdout__.flush()
                #sys.__stderr__.flush()
                try:
                    t.terminate()
                    t.join()    
                except:
                    continue
                            
            sys.__stdout__.write(CYAN + "[^_^] Thanks for using Mutiny!\n" + CLEAR)
            sys.__stdout__.flush()
            return

        output("[!.!] Feedback ready!","fuzzer",print_queue,thread,GREEN)

    fuzzer_threads = []
    for thread in range(0,instance_count): 
        fuzzer_thread = multiprocessing.Process(target = fuzz_target,
                                                  args = (logs,
                                                          fuzzer_count,
                                                          crash_count,
                                                          new_count,
                                                          fuzzer_queue,
                                                          inbound_queue_list[thread],
                                                          print_queue,
                                                          thread,
                                                          kill_switch,
                                                          fuzz_flag_list[thread])) 
        fuzzer_thread.name = "fuzz-target-%d"%i
        fuzzer_threads.append(fuzzer_thread)
        thread_list.append(fuzzer_thread)
        fuzzer_threads[-1].start()

    try:
        for t in thread_list:
            try:
                t.join()
            except KeyboardInterrupt:
                raise
            except:
                continue
    except KeyboardInterrupt:
        kill_switch.set()
        
    for tq in inbound_queue_list:
        while not tq.empty():
            tq.get()
    '''
    while not outbound_queue.empty():
        outbound_queue.get()
    '''
    while not print_queue.empty():
        print_queue.get()
    while not fuzzer_queue.empty():
        fuzzer_queue.get()

    for t in thread_list:
        try:
            t.terminate()
            t.join()    
        except:
            continue

    sys.__stdout__.write(CYAN + "[^_^] Thanks for using Mutiny!\n" + CLEAR)
    sys.__stdout__.flush()


def fuzz_target(logs,fc,cc,nc,fq,inbound_queue,print_queue,instance_num,kill_switch,fuzz_case_flag):

    # Send a sample testcase for the baseline
    resp = "" 
    output("[i.i] Blocking till Mutiny's campaign socket connected. ","fuzzer",print_queue,instance_num)
    # Block till new mutiny instance is up.
    fuzzer_count = fc
    crash_count = cc
    new_count = nc
    fuzzer_queue = fq

    while True:
        if kill_switch.is_set():
            return

        try:
            mutiny_control_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
            mutiny_control_sock.connect((IP,CAMPAIGN_PORT+(3*instance_num))) 
            break
        except Exception as e:
            output(str(e),"fuzzer",print_queue) 
            time.sleep(1)
            continue

    mutiny_control_sock.send("go")            
    resp = get_bytes(mutiny_control_sock) 
    time.sleep(1)

    output("[1.1] Mutiny campaign socket connected!","fuzzer",print_queue,instance_num)
    curr_seed = -1
    curr_msg = -1
    curr_submsg = -1

    try:
        while True:
            if kill_switch.is_set():
                try:
                    mutiny_control_sock.send("di")
                except:
                    pass
                break

            # block here/wait till we get a message
            if fuzz_case_flag.is_set():
                resp = ""

                try:
                    if "--debug" in sys.argv:
                        raw_input("[?_?] Send next seed?")
                    mutiny_control_sock.send("go")
                except Exception as e:
                    # Block till new mutiny instance is up.
                    output("[i.i] Blocking till Mutiny's campaign socket connected. ","fuzzer",print_queue,instance_num)
                    while True:
                        if kill_switch.is_set():
                            break
                        try:
                            mutiny_control_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM) 
                            mutiny_control_sock.connect((IP,CAMPAIGN_PORT+(3*instance_num))) 
                            break
                        except Exception as e:
                            #output(str(e),"fuzzer",print_queue) 
                            time.sleep(1)
                            continue

                try:
                    resp = get_bytes(mutiny_control_sock,timeout=1,bytecount=128)
                    #output("resp ? %s"%resp,"fuzzer",print_queue)
                except Exception as e:
                    output("resp socket error: %s"%str(e),"fuzzer",print_queue)
                    pass
        
                if resp:
                    try:
                        # this is fine/synced.
                        # resp should be csv of (curr_seed,curr_msg,curr_submsg)
                        #output("resp: %s"%resp,"fuzzer",print_queue) 
                        curr_seed,curr_msg,curr_submsg = filter(None,resp.split(","))
                        curr_seed = int(curr_seed) 
                        curr_msg = int(curr_msg) 
                        curr_submsg = int(curr_submsg) 
                        update_curr_msg(resp,print_queue,instance_num)

                    except ValueError as e:
                        #output("Campaign value error: %s"%str(e),"fuzzer",print_queue)
                        continue

                    except Exception as e:
                        output("General campaign socket error: %s"%str(e),"fuzzer",print_queue)
                        pass


            try:
                msg = inbound_queue.get_nowait()
                if len(msg):
                    # pause so there's no amibuity 

                    msg_type = msg.split("\n")[0]
                    if msg_type == "save_queue":   
                        fuzz_case_flag.clear()
                        try:
                            # are we not reading these fast enough...?
                            #output("[5.5] saving dump","fuzzer",print_queue,instance_num)
                            mutiny_control_sock.send("de")
                            #output("[5.5]sent to campaign... :(","fuzzer",print_queue,instance_num)
                            fuzzer_file = get_bytes(mutiny_control_sock,timeout=1)
                            #output("[5.5 got %d bytes back...... :("%len(fuzzer_file),"fuzzer",print_queue,instance_num)
                            # this isfailing? 
                            fuzzer_loc = os.path.join(queue_dir,"id_%08d_%d_%d_%d_delim" % (fuzzer_count,curr_seed,curr_msg,curr_submsg)) 
                            output("[5.5] Requesting %s to queue"%fuzzer_loc,"fuzzer",print_queue,instance_num)
                            
                            if fuzzer_file:
                                test_ind = fuzzer_file.find("'''") # if there's anything else on the socket when we do this,
                                                                   # there's occasionally %d,%d,%d entries before the dump, 
                                                                   # which we really don't care about.  
                                #while test_ind == -1:
                                #        output("Invalid fuzzer dump received, trying again...","fuzzer",print_queue,instance_num)
                                #        fuzzer_file = get_bytes(mutiny_control_sock,timeout=1)
                                #        test_ind = fuzzer_file.find("'''") # if there's anything else on the socket when we do this,
                                
                                with open(fuzzer_loc,"w") as f:
                                    #f.write(fuzzer_file[test_ind:])
                                    f.write(fuzzer_file)
                                    output("[5.5] Added %s to queue"%fuzzer_loc,"fuzzer",print_queue)
                                    try:
                                        update_feedback_stats(crash_count,fuzzer_count,new_count,print_queue,instance_num)
                                    except:
                                        oops()

                                    fuzzer_count+=1
                                    new_count+=1
                                fuzzer_queue.put(fuzzer_loc) 
                            else:                    
                                output("[5.5] no resp from campaign... :(","fuzzer",print_queue)

                            mutiny_control_sock.send("fd")
                            fuzzer_file = get_bytes(mutiny_control_sock,timeout=1)
                            fuzzer_loc = os.path.join(queue_dir,"id_%08d_%d_%d_%d_full" % (fuzzer_count,curr_seed,curr_msg,curr_submsg)) 
                            #output("[5.5] Requesting %s to queue"%fuzzer_loc,"fuzzer",print_queue)
                            if fuzzer_file:
                                #! so the current issue is that > than 
                                test_ind = fuzzer_file.find("'''") # if there's anything else on the socket when we do this,
                                                                   # there's occasionally %d,%d,%d entries before the dump, 
                                                                   # which we really don't care about.  
                                #while test_ind == -1:
                                #        output("Invalid full fuzzer dump received, trying again...","fuzzer",print_queue,instance_num)
                                #        fuzzer_file = get_bytes(mutiny_control_sock,timeout=1)
                                #        test_ind = fuzzer_file.find("'''") # if there's anything else on the socket when we do this,

                                with open(fuzzer_loc,"w") as f:
                                    #f.write(fuzzer_file[test_ind:])
                                    f.write(fuzzer_file)
                                    #output("[5.5] Added %s to queue"%fuzzer_loc,"fuzzer",print_queue)
                                    try:
                                        update_feedback_stats(crash_count,fuzzer_count,new_count,print_queue,instance_num)
                                    except:
                                        oops()
                                    fuzzer_count+=1
                                fuzzer_queue.put(fuzzer_loc) 

                            # resume.
                            fuzz_case_flag.set()
                        except Exception as e:
                            output("[?.?] Fuzzcase queue'ing error: %s"%str(e),"fuzzer",print_queue,instance_num)

                        fuzz_case_flag.set()

                    elif msg_type == "save_crash":   
                        fuzz_case_flag.clear()
                        crash = msg[10:] 
                        logs.write("resp:%s" % str(crash))
                        mutiny_control_sock.send("fulldump")
                        crash_loc = os.path.join(crash_dir,"id_%08d_%d_%d_%d" % (fuzzer_count,curr_seed,curr_msg,curr_submsg)) 
                        fuzzer_count+=1

                        # in case there was extra data
                        if len(dumped_fuzzer) < 20:
                            dumped_fuzzer = get_bytes(mutiny_control_sock) 

                        with open(fuzzer_loc,"w") as f:
                            f.write(dumped_fuzzer)

                        # add to queue
                        logs.write("\n*******************\n") 
                        logs.write(str(datetime.datetime.now()) + "\n")
                        logs.write("Seed: " + str(curr_seed) + "\n")
                        logs.write("\n*******************\n") 
                        logs.write("******CRASH*******\n") 
                        logs.write(crash)
                        logs.write("*******************\n") 
                        #logs.write(dumped_fuzzer)
                        #logs.write("*******************\n") 
                        logs.flush()
                        ret = block_till_feedback_ready(inbound_queue)
                        if ret == -1:
                            kill_switch.set()

                        crash_count +=1
                        fuzzer_count +=1
                        new_count +=1
                        try:
                            update_feedback_stats(crash_count,fuzzer_count,new_count,print_queue,instance_num)
                        except: 
                            oops()
                        fuzz_case_flag.set()
    
                    elif msg_type == "shutdown_data":   
                        msg_data = msg[13:] 
                        # ????
                        kill_switch.set()

                    elif msg_type == "timeout":
                        SOCKTIMEOUT = SOCKTIEMOUT*2
                        output("Increasing sockettimeout to %f"%SOCKTIMEOUT,"fuzzer",print_queue,instance_num)
                        fuzz_case_flag.set()

                    elif msg_type == "pause":
                        fuzz_case_flag.clear() 
                        continue

                    elif msg_type == "resume":
                        fuzz_case_flag.set()
                        continue

                    elif msg_type == "mini_init":
                        output("[o] Pausing feedback for minimization!","fuzzer",print_queue,instance_num,GREEN)
                        new_fuzzer_queue = multiprocessing.Queue() 
                        fuzz_case_flag.clear()
                        mini_dst = os.path.join(fuzzer_dir,"minimized")
                        
                        mini_dict = do_minimization(mini_dst,fuzzer_queue,mutiny_args[:],print_queue,kill_switch,instance_num) 

                        mini_trace_file = os.path.join(fuzzer_dir,"mini_dict_result.txt-%d"%instance_num)
                        output("[o.o] Writing mini_dict to %s"%mini_trace_file,"fuzzer",print_queue,GREEN,instance_num)

                        trace_buf = ""
                        if mini_dict:
                            for entry in mini_dict:
                                trace_buf+="%s\n%s\n"%(entry,mini_dict[entry])

                            with open(mini_trace_file,"w") as f:
                                f.write(trace_buf)

                                os.mkdir(mini_dst)
                                try:
                                    for entry in mini_dict:
                                        new_fuzzer_queue.put(entry)
                                        file_copy_dst = os.path.join(mini_dst,os.path.basename(str(entry)))
                                        output("%s => %s"%(str(entry),str(file_copy_dst)),"fuzzer",print_queue,color=CYAN)
                                        with open(entry,"r") as src:
                                            with open(file_copy_dst,"w") as dst:
                                                dst.write(src.read())
                                except Exception as e:
                                    output("[x.x] Couldn't do the stuff: %s"%str(e),"fuzzer",print_queue,color=GREEN)
                            
                                fuzzer_queue = new_fuzzer_queue 
                                output("[o] Resuming feedback for minimization!","fuzzer",print_queue,color=GREEN)
                                fuzz_case_flag.set()
                        else:    
                            output("[x.x] minimization => no results.","fuzzer",print_queue) 

                        continue 

                    else:
                        output("Data on inbound_queue: %s" % msg,"fuzzer",print_queue)


            except Queue.Empty:
                pass
            except Exception as e:
                if "Broken pipe" in e:
                    continue
                pass
                
    except KeyboardInterrupt:
        kill_switch.set()

    

def get_bytes(sock,timeout=SOCKTIMEOUT,bytecount=65535):
    ret = ""
    sock.settimeout(timeout)
    try:
        while True:
            tmp = sock.recv(bytecount)
            if len(tmp) > 0:
                ret+=tmp
                if bytecount != 65535:
                    return ret
            else:
                break
    except Exception as e:
        pass

    return ret


# block here until we have a feedback connection.
def block_till_feedback_ready(inbound_queue,kill_switch):
    while True:
        if kill_switch.is_set():
            return -1
        try:
            ready = inbound_queue.get()
            if ready.split('\n')[0] == "feedback_connected":
                break 
            else:
                print "[?_?] Inbound msg: %s" % str(ready)
        except:
            time.sleep(1)

    
# inbound refers to 'inbound' to control thread.
# outbound refers to 'outbound' to this thread from control thread.
def feedback_listener(inbound_queue,kill_switch,fuzz_case_flag,print_queue,instance_num):

    cli_sock = None
    cli_addr = None
    outbound_msg = ""
    inbound_msg = ""
    init_str = ""

    shutdown_flag = False

    harness_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    harness_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    harness_socket.bind((FEEDBACK_IP,FEEDBACK_PORT+(3*instance_num)))
    harness_socket.listen(1)
    output("[^_^] Feedback bound %s:%d"%(FEEDBACK_IP,FEEDBACK_PORT),"fuzzer",print_queue,instance_num,GREEN)
   
    while True:
        try:
            if kill_switch.is_set():
                break

            # Lock here till the feedback connects back
            cli_sock,cli_addr = harness_socket.accept() 
            cli_sock.settimeout(1)
            while not len(init_str):
                init_str = get_bytes(cli_sock)

            if init_str != "boop":
                output("[>_<] Bad client init recv'ed, killing connection (%s:%d)"%cli_addr,"fuzzer",print_queue,instance_num,YELLOW) 
                cli_sock.close()
                continue

            cli_sock.send("doop")
            inbound_queue.put("feedback_connected\n")
            output("[^_^] Feedback handshake successful!","fuzzer",print_queue,instance_num)

            while True:
                if kill_switch.is_set():
                    break
                '''
                try:
                    # check to see if remote sock still open.
                    if fuzz_case_flag.is_set():
                        cli_sock.send(FUZZ_CASE) 
                except Exception as e:
                    fuzz_case_flag.clear()
                    cli_sock.close()
                    output("[^_^] Re-establishing feedback harness (err: %s)"%str(e),"fuzzer",print_queue,instance_num)
                    cli_sock,cli_addr = harness_socket.accept() 
                    cli_sock.settimeout(1)
                    continue
                '''

                '''
                # check if fuzzer wants to send any msg to the feedback engine
                try:
                    outbound_msg = outbound_queue.get_nowait()
                    #print "Sending %s to fuzzer!" % repr(outbound_msg)
                    if outbound_msg != "": 
                        # process/send msg to feedback_daemon
                        # Messages are correctly packaged by the thread that put
                        # the message into the outbound_queue
                        try:
                            cli_sock.send(outbound_msg)
                        except:
                            output("[;_;] Could not send %s! Restarting socket!"%outbound_msg,"fuzzer",print_queue,instance_num,YELLOW)
                            cli_sock.close()
                            break
                except Queue.Empty:
                    pass
                except Exception as e:
                    if "Broken pipe" in e:
                        print "[;_;] %s"%e
                    output("[;_;] %s"%e,"fuzzer",print_queue,instance_num,YELLOW)
                '''
                
                inbound_msg = get_bytes(cli_sock)

                #if inbound_msg and len(inbound_msg) < 50:
                #    print repr(inbound_msg)

                if inbound_msg != "" and (len(inbound_msg) >= 5):           
                    for i in range(0,len(inbound_msg),5):
                        msg_chunk = inbound_msg[i:i+5]
                        # redo handshake as needed. 
                        if msg_chunk  == "boop":
                            inbound_queue.put("feedback_connected\n")
                            cli_sock.send("doop")
                        elif msg_chunk == HEARTBEAT:
                            #HEARTBEAT            = "\x0F\x00\x00\x00\x00"
                            cli_sock.send(HEARTBEAT)
                        else: 
                            fuzz_case_flag.clear() 
                            #if len(msg_chunk) < 5:
                                 
                            # validate the message/see if it's a good msg.                
                            ret_tup = validate_feedback(msg_chunk)
                            if ret_tup:
                                try:
                                    t,l = ret_tup
                                    value = ""
                                    if l > 0:
                                        value = inbound_msg[i+5:i+5+l]
                                        i+=l
                                    
                                    message = opcode_dict[t] 
                                    if message:
                                        #output("[?.?] Message type received: %s"%message, "fuzzer",print_queue,instance_num,GREEN)
                                        inbound_queue.put(message + '\n' + str(value))
                                except Exception as e:
                                    output("validate_feedback error: %s" % str(e),"fuzzer",print_queue,instance_num,YELLOW)
                                    continue
                    
        except KeyboardInterrupt:
            if cli_sock:
                cli_sock.close()
            kill_switch.set()
            break

    #sys.__stdout__.write(GREEN + "\n[*.*] feedback_listener thread cleaned up\n" + CLEAR)
    #sys.__stdout__.flush()


def validate_feedback(inbound):
    t = "" # type
    l = "" # length
    v = "" # value
    
    '''
    if len(inbound) < 1000: 
        print "Validating: %s" % repr(inbound)
    else:
        print "Huge msg (0x%x): %s" % (len(inbound),repr(inbound[0:100]))
        #raw_input('[->-]')
    '''

    try:
        t = ord(inbound[0])
        l = struct.unpack("<I",inbound[1:5])[0]
    except IndexError as e:
        raise e
        return ()
    except Exception as e:
        raise e
        return ()

    # 0x10 bit marks direction.
    if (t & 0x10) == 0:
        return ()

    # MAX_MSG_SIZE => 0x10000
    if l < 0 or l > 0x10000: 
        return ()

    return (t,l)

    return None

def launch_corpus(fuzzer_dir,append_lock,fuzzer_queue,kill_switch,fuzz_case_flag,mutiny_args,print_queue,tmp_list,thread_num):
    timeout = FUZZERTIMEOUT
    repeat_counter = 0
    crash_dir = os.path.join(fuzzer_dir,"crashes")
    queue_dir = os.path.join(fuzzer_dir,"queue")
    processed_dir = os.path.join(fuzzer_dir,"processed")

    processed_count = 0
    repeat_flag = False
    
    if "--skip-unfuzzed" in mutiny_args:
        mutiny_args.remove("--skip-unfuzzed")
    else:
        output("[^_^] Rotating over initial corpus unfuzzed","fuzzer",print_queue,color=CYAN)
        unfuzzed_list = tmp_list[:] 
         
        while len(unfuzzed_list):
            fuzzer_file = unfuzzed_list.pop()
            output('[o.o] Testing unfuzzed (%d left): %s'%(len(unfuzzed_list),fuzzer_file),"fuzzer",print_queue,thread_num)

            tmp_args = [ 
                 fuzzer_file,
                 "-i", target_ip,    
                 "-r", "unfuzzed",
                 "--quiet",
                 "--timeout",".05"
               ]                
            

            if "-p" in mutiny_args:
                try:
                    ind = mutiny_args.index("-p")+1
                    tmp_args.append("-p")
                    tmp_args.append(str(int(mutiny_args[ind])+(thread_num)))
                except Exception as e:
                    output("[>_>] Invalid args given: %s" % str(mutiny_args),"fuzzer",print_queue,thread_num)
                    pass

            try:
                fuzzy = get_mutiny_with_args(tmp_args)
            except Exception as e: 
                output("[>_>] Invalid args given: %s" % str(tmp_args),"fuzzer",print_queue)
                output("%s" %str(e),"fuzzer",print_queue)
                continue
            
            try:
                fuzzy.monitor.lockExecution() # must specify since normally mutiny doesn't wait
                fuzzy.fuzz()                  # when doing an unfuzzed case.
                fuzzy.sigint_handler(-1)
            except Exception as e: 
                try:
                    last_logs = fuzzy.important_messages[-2:] + fuzzy.fuzzer_messages[-2:]
                    for ll in last_logs:
                        output("Mutiny log: %s"%ll,"fuzzer",print_queue,thread_num)
                        output("            %s"%str(e),"fuzzer",print_queue,thread_num)
                except:
                    output("[x.x] Mutiny fuzz error: %s"%e,"fuzzer",print_queue,thread_num)
                    continue
                     
        
        if thread_num == 0:
            output("[^_^] Done rotating over initial corpus","fuzzer",print_queue,thread_num,color=GREEN)
            output("      Please start feedback with `boop feedback` in gluttony","fuzzer",print_queue,color=GREEN)
            output("      or minimization with `boop mini`","fuzzer",print_queue,color=GREEN)
    
    lowerbound = 0
    upperbound=0
    while True:
        try:
            # check for new fuzzers if using shared corpus.
            if fuzzer_queue.empty():    
                output("[._.] Fuzzer queue empty, taking actions...","fuzzer",print_queue,color=YELLOW)
                append_lock.acquire()
                new_fuzzer_list = os.listdir(queue_dir)
                for f in filter(None,new_fuzzer_list):

                    if f.startswith(".") or f.endswith(".swp") or f.endswith(".swo"):
                        continue

                    if f.endswith("py") or f.endswith("pyc"):
                        continue

                    fname = os.path.join(queue_dir,f)

                    if os.path.isdir(fname): 
                        continue

                    fuzzer_queue.put(fname) 
            
                    time.sleep(.01)
                append_lock.release()

            # did we get anything? no? then just repopulate and hit next set of seeds.
            if fuzzer_queue.empty():    
                output("[._.] Starting on next set of seeds.","fuzzer",print_queue,color=YELLOW)
                append_lock.acquire()
                repeat_counter += 1
                processed = os.listdir(processed_dir)
                for f in processed:
                    fuzzer_queue.put(os.path.join(processed_dir,f)) 
                    time.sleep(.01)
                append_lock.release()
                    
            if repeat_flag:
                # repeat last fuzzer.
                repeat_flag = False
                output("[v.v] Sleeping 3, then repeating failed fuzzy.fuzz()","fuzzer",print_queue)
                time.sleep(3)
   
            elif not repeat_flag:
                append_lock.acquire()
                fuzzer = fuzzer_queue.get()
                # isn't it sync'ed anyways?
                append_lock.release()

                if not os.path.isfile(fuzzer):
                    continue # corpus minimizer might have removed.

                with open(fuzzer,"rb") as f:
                    tmp = f.read()
                    # quick sanity check
                    if "outbound fuzz" not in tmp and "more fuzz" not in tmp:
                        continue

            amt_per_fuzzer = 10000
            try:
                ind = mutiny_args.index("-r") 
                lowerbound,upperbound = [int(x) for x in mutiny_args[ind+1].split("-")]
                amt_per_fuzzer = upperbound - lowerbound
                try:
                    mutiny_args = mutiny_args[:ind] + mutiny_args[ind+2:]
                except IndexError:
                    mutiny_args = mutiny_args[:ind] 
            except ValueError:
                
                lowerbound = lowerbound + (amt_per_fuzzer * repeat_counter) 
                upperbound = lowerbound + (amt_per_fuzzer * (repeat_counter+1)) 

            mutiny_args.append("-r")
            mutiny_args.append("%d-%d"%(lowerbound + (amt_per_fuzzer*repeat_counter),lowerbound+(amt_per_fuzzer*(repeat_counter+1))))
            
            update_curr_fuzzer((fuzzer,lowerbound,upperbound),print_queue,thread_num)

            try:
                args = []
                if not mutiny_args:
                    args = [fuzzer,
                            "--campaign",str(CAMPAIGN_PORT+(3*thread_num)),
                            "-r","%d-%d"%(lowerbound,upperbound),
                            # we want to wait until it's done.
                            "-t",str(timeout), 
                            "-i",target_ip,
                            #"-R",str(amt_per_fuzzer),
                            "--quiet"
                    ]
                else:
                    try:
                        args = [ fuzzer,  
                                 "--campaign",str(CAMPAIGN_PORT+(3*thread_num)),
                                 "-i", target_ip,    
                                 "--quiet"
                               ]                

                        if "-p" in mutiny_args:
                            try:
                                ind = mutiny_args.index("-p")
                                args.append("-p")
                                args.append(str(int(mutiny_args[ind+1])+(thread_num)))
                                args += mutiny_args[:ind] + mutiny_args[ind+2:]
                            except IndexError:
                                args += mutiny_args[:ind] 
                            except:
                                args += mutiny_args 
                        
                        else:
                            args += mutiny_args 

                            
                        if "-t" not in mutiny_args and "--timeout" not in mutiny_args:
                            args.append("-t")
                            args.append(str(timeout)) 
                            output("Setting timeout to %s" %str(timeout),"fuzzer",print_queue,thread_num)
                        
                    except:
                        oops()
                
                logger.write("\n-------------------------------\n")
                logger.write(str(datetime.datetime.now()) + "\n")
                logger.write("Starting on %s (%d-%d)\n" %(fuzzer,lowerbound,upperbound))
                logger.write("#!")
                logger.write(str(args))
                logger.write("\n-------------------------------\n")
                logger.flush()
                
                output("Launching new mutiny: %s" %str(args),"fuzzer",print_queue,thread_num)

                try:
                    update_processed_stats(processed_count,print_queue,thread_num)
                except:
                    oops()
            
                try:
                    fuzzy = get_mutiny_with_args(args)
                except Exception as e: 
                    output("%s" %str(e),"fuzzer",print_queue,thread_num)
                    continue
                
                try:
                    fuzzy.fuzz()
                    fuzzy.sigint_handler(-1)
                except Exception as e: 
                    output("No fuzz, only %s" %str(e),"fuzzer",print_queue,thread_num)
                    try:
                        last_logs = fuzzy.important_messages[-4:] + fuzzy.fuzzer_messages[-4:]
                        for ll in last_logs:
                            output("Mutiny log: %s"%ll,"fuzzer",print_queue)
                    except:
                        output("[x.x] Mutiny fuzz error: %s"%e,"fuzzer",print_queue,thread_num)

                    repeat_flag = True
                    continue
                        
                        

                processed_count+=1
                # Move over to processed_fuzzer dir if we got through entire fuzzer. 
                try:
                    dst_path =  os.path.join(processed_dir,os.path.basename(fuzzer)) 
                    os.rename(fuzzer, dst_path)
                    output("[!] Finished %s" % (fuzzer),"fuzzer",print_queue) 
                except:
                    continue
        
            except Exception as e:
                oops()
                output(str(e),"fuzzer",print_queue) 
                logger.write(str(e))
                logger.flush()
        
    
        except KeyboardInterrupt:   
            break

        except Exception as e:
            output("launch_corpus error: %s" % str(e),"fuzzer",print_queue,color=YELLOW)
            traceback.print_exc()

    kill_switch.set()
    #sys.__stdout__.write(GREEN + "\n[*.*] launch_corpus thread cleaned up\n" + CLEAR)
    #sys.__stdout__.flush()


# Polling cuz we don't have that much of a rush.
def corpus_minimizer(fuzzer_dir,kill_switch,print_queue):
    import md5
    corpus_dict = {}
    fuzzer_list = []
    old_fuzzer_list = []
    queue_dir = os.path.join(fuzzer_dir,"queue")

    while not kill_switch.is_set():
        try: 
            time.sleep(60) # like I said, no rush. 
            fuzzer_list = os.listdir(queue_dir)
            for fuzzer in fuzzer_list:

                if fuzzer not in old_fuzzer_list:
                    fpath = os.path.join(queue_dir,fuzzer)

                    try:
                        with open(fpath,"rb") as f:
                            inp = f.read()
                            if not inp:
                                os.remove(fpath)
                                continue
                
                            if "outbound fuzz ''" in inp:
                                os.remove(fpath)
                                continue

                            fuzzer_hash = md5.new(inp).digest()
                    except:
                        continue
                   
                    try:
                        corpus_dict[fuzzer_hash]+=1
                        os.remove(fpath) # md5 already in dict => dup
                    except:
                        corpus_dict[fuzzer_hash] = 1
                  
            old_fuzzer_list = os.listdir(queue_dir)          
        except KeyboardInterrupt:
            break
        except:
            continue
   
    #sys.__stdout__.write(GREEN + "\n[*.*] Minimizer thread cleaned up\n" + CLEAR)
    #sys.__stdout__.flush()
    '''
    try:
        with open(os.path.join(fuzzer_dir,"corpus_statistics.txt"),"wb") as f: 
            f.write(corpus_dict)
    except:
        pass
    '''

# This function returns a list of fuzzers that represent the 
# minimized corpus.
# This function drains out the fuzzer_queue and will not replace it.
def do_minimization(dst_dir,fuzzer_queue,mutiny_args,print_queue,kill_switch,instance_num):
    mini_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    mini_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mini_socket.bind((MINIMIZE_IP,MINIMIZE_PORT+(3*instance_num)))
    mini_socket.listen(2)
  
    init_str = ""
    mini_trace_bb_list = []
    mini_trace_fuzzer_dict = {}
    
    cli_sock = None
    cli_addr = None
    first_send_flag = True

    while True:
        if kill_switch.is_set():
            break

        # Lock here till the feedback connects back
        if not cli_sock:
            output("[*] Listening for minimization connectionn...","fuzzer",print_queue,color=GREEN)
            cli_sock,cli_addr = mini_socket.accept() 
            output("[*] Minimization connection gotted...","fuzzer",print_queue,color=GREEN)

        init_str = get_bytes(cli_sock)
        if init_str != "mini_mini": 
            continue
        cli_sock.send("mini_mini_mini")
        time.sleep(3)

        initial_len = fuzzer_queue.qsize()

        # repopulate all the processed fuzzers
        for processed in os.listdir(processed_dir):
            if ".swp" in processed:
                continue
            fuzzer_queue.put(os.path.join(processed_dir,processed))
            time.sleep(.1)
        

        while True:
            # start iterating over the fuzzer_queue.
            if fuzzer_queue.empty():
                break
            
            fuzzer = fuzzer_queue.get()

            if not os.path.isfile(fuzzer):
                continue # corpus minimizer might have removed.

            with open(fuzzer,"rb") as f:
                tmp = f.read()

                # quick sanity check
                if "outbound fuzz" not in tmp and "more fuzz" not in tmp:
                    continue
        
            args = [fuzzer,
                    "-r","unfuzzed",
                    # we want to wait until it's done.
                    #"-t",str(timeout),
                    "-i",target_ip,
                    "--quiet"
            ]
        
            if mutiny_args:
                 if "-p" in mutiny_args:
                        try:
                            ind = mutiny_args.index('-p')
                            new_port = int(mutiny_args[ind+1])
                            mutiny_args = mutiny_args[:ind] + instance_num 
                        except:
                            pass
           
                 args += mutiny_args

            output("[*] Loading up mutiny w/args: %s"%str(args),"fuzzer",print_queue,color=CLEAR)
            try:
                fuzzy = get_mutiny_with_args(args)
            except Exception as e:
                output("%s" %str(e),"fuzzer",print_queue)
                continue
               
            output("[^_^] Fuzzers left %d/%d"%(fuzzer_queue.qsize()+1,initial_len),"fuzzer",print_queue,color=CYAN) 

            if first_send_flag: 
                cli_sock.send(str(FUZZ_CASE)) # \x03\x00\x00\x00\x00
                first_send_flag = False
                # gluttony resets trace data at this point
                # need to wait till gluttony is finished
                output("[*] Waiting for trace finish...","fuzzer",print_queue,color=GREEN)

            tmp_msg = ""
            while not tmp_msg:
                tmp_msg = get_bytes(cli_sock,bytecount=5) 
                if tmp_msg:
                    try:
                        if opcode_dict[ord(tmp_msg[0])] == "mini_ready":
                            #output("[*] Trace finish gotted","fuzzer",print_queue,GREEN)
                            break 
                        else: 
                            output("[*] Got weird beyts:%s"%tmp_msg,"fuzzer",print_queue,color=YELLOW)
                            tmp_msg = ""
                    except Exception as e:
                        output("[*] Got weird error:%s"%str(e),"fuzzer",print_queue,color=YELLOW)
                        tmp_msg = ""
                time.sleep(1)

            #output("[*] Sending fuzz_case_done...","fuzzer",print_queue,GREEN)
            try:
                cli_sock.send(str(FUZZ_CASE_DONE)) # \x04\x00\x00\x00\x00
                #output("[*] Sendt fuzz_case_done...","fuzzer",print_queue,GREEN)
            except BrokenPipeError:
                # feedback reset or something, ignore and re-establish/retry this case.
                fuzzer_queue.put(fuzzer)
                cli_sock = None
                break

            #output("[*] Sent fuzz_case_done...","fuzzer",print_queue,GREEN)

            #output("[*] Fuzzing...","fuzzer",print_queue,GREEN)

            try:
                fuzzy.fuzz()
                fuzzy.sigint_handler(-1)
            except:
                try:
                    last_logs = fuzzy.important_messages[-2:] + fuzzy.fuzzer_messages[-2:]
                    for ll in last_logs:
                        output("Mutiny log: %s"%ll,"fuzzer",print_queue)
                        output("            %s"%str(e),"fuzzer",print_queue)
                except:
                    output("[x.x] Mutiny fuzz error: %s"%e,"fuzzer",print_queue)
                    continue

                continue

            
            tmp_msg = ""
            try:
                #output("[*] Waiting for ret trace buffer...","fuzzer",print_queue,color=GREEN)
                while not tmp_msg:
                    tmp_msg = get_bytes(cli_sock,bytecount=5) 
                    time.sleep(1)
            except Exception as e:
                # feedback reset or something, ignore and re-establish/retry this case.
                output("[?.?] str(e) => %s"%str(e),print_queue,color=YELLOW)
                output("[v.v] Empty msg recv'd","fuzzer",print_queue,color=YELLOW)
                fuzzer_queue.put(fuzzer)
                cli_sock = None
                continue

            #output("[<.<] Received buffer, %s"%repr(tmp_msg),"fuzzer",print_queue,CYAN)
            msg_len = -1 
            msg_body = ""

            if tmp_msg:
                # make sure valid message type:
                try:
                    if opcode_dict[ord(tmp_msg[0])] != "mini_result":
                        output("invalid opcode 0x%x"%ord(tmp_msg[0]),"fuzzer",print_queue,color=YELLOW)
                        # try another fuzzer I guess?
                        continue  
                    msg_len = struct.unpack(">I",tmp_msg[1:5])[0]         

                except Exception as e:
                    output('[x.x] Exception hit from feedback msg: %s'%e,"fuzzer",print_queue,color=YELLOW)
                    continue
                
                msg_body = get_bytes(cli_sock,bytecount=msg_len)
                if not msg_body:
                    output("[x.x] Empty message body from feedback","fuzzer",print_queue,color=YELLOW)


                # need to make sure msg_body is intelligable and easy to parse.
                try:
                    mini_trace_fuzzer_dict = add_to_minimized_if_better(mini_trace_bb_list,fuzzer,msg_body,mini_trace_fuzzer_dict,print_queue)
                    #output("[<.<] mini_trace_fuzzer_dict %s"%repr(mini_trace_fuzzer_dict),"fuzzer",print_queue,GREEN)
                except Exception as e:
                    output('[x.x] Exception hit add_to_minimized:  %s'%e,"fuzzer",print_queue,color=YELLOW)
                continue
            else:
                output("[x.x] Empty message from feedback","fuzzer",print_queue,color=YELLOW)
                time.sleep(1)
                continue

        if fuzzer_queue.empty():
            break

    try: 
        output("[!.!] Sending Trace done!","fuzzer",print_queue,color=YELLOW)
        cli_sock.send(str(TRACE_DONE)) # \x05\x00\x00\x00\x00
    except:
        pass

    output("[<.<] Done minimizing, unique entries: %d"%len(mini_trace_fuzzer_dict),"fuzzer",print_queue,color=GREEN)
    return mini_trace_fuzzer_dict


# there's probably some bullshit datastructure suited for this...
def add_to_minimized_if_better(curr_bb_list, fuzzer_name, msg_body, curr_trace_dict, print_queue):

    trim_entry_flag = True
    subset_flag = True
    add_new_flag = False
    delete_list = []

    # format new trace as needed 
    new_trace = msg_body.split(",") # str => list 
    
    # if already in dict, return
    if new_trace in curr_trace_dict.values():
        output("[;_;] No new basic blocks","fuzzer",print_queue,color=YELLOW) 
        return curr_trace_dict    

    # only python3 has list.issubset(), list.intersection... [>_>]
    for entry in new_trace:
        if entry not in curr_bb_list:
            subset_flag = False
            add_new_flag = True
            output("[;_;] Adding new trace %s, %s"%(repr(entry),repr(new_trace)),"fuzzer",print_queue,color=GREEN) 
            break 
                
    # Regardless of if it's a subset or not, we still need to optimize. 
    # Make sure that there's no current entries that are subsets of the new one.
    for entry in curr_trace_dict:
        trim_entry_flag = True
        bb_list = curr_trace_dict[entry]
        for i in range(0,len(bb_list)):
            bb = bb_list[i]

            try:
                if bb != new_trace[i]:
                    trim_entry_flag = False
                    break
            except IndexError:
                trim_entry_flag = False
                break

        if trim_entry_flag:
            delete_list.append(entry)
            add_new_flag = True
            output("[;_;] Subset found, remove: %s"%(repr(entry)),"fuzzer",print_queue,color=YELLOW) 
        
    # we add only if one of the following conditions:
    # 1. There are new basic blocks that we have not seen.
    # 2. We optimized and removed older entries in favor of new ones.

    if add_new_flag:
        curr_trace_dict[fuzzer_name] = new_trace    
        for entry in delete_list:
            # have to do this seperate as python doesn't like changing dicts during iter. 
            del(curr_trace_dict[entry])
    
    return curr_trace_dict
    

def update_curr_msg(curr_msg,queue,thread_num=0):
    output(curr_msg,"curr_msg",queue,thread_num)

def update_curr_fuzzer(curr_fuzzer,queue,thread_num=0):
    output(curr_fuzzer,"curr_fuzzer",queue,thread_num)

def update_feedback_stats(crashes,fuzzers,new,queue,thread_num=0):
    output((crashes,fuzzers,-1,new),"stats",queue,thread_num)

def update_processed_stats(processed_count,queue,thread_num=0):
    output((-1,-1,processed_count,-1),"stats",queue,thread_num)

def output(inp,inp_type,queue,thread_num=-1,color=""):
    queue.put((inp,inp_type,color,thread_num)) 

###########################################
# expect entries into inp queue like ("<msg>","<catagory>",COLOR)
def output_thread(inp_queue,fuzz_flag_list,kill_switch,instance_count=0):
    fuzzer_log_messages = []
    update_fuzzer_log_messages = False
    output_width = 48
    
    # Output => pretty. Yay.
    stat_messages = CLEAR + " Total Runtime : %s %s \n" \
                  + " Crash Counter : %d " \
                  + " | "  + " LastCrash %s\n" \
                  + " Queued Fuzzers: %d " \
                  + " | "  + " LastNewQueue %s \n" \
                  + " Fuzzers Done  : %d " \
                  + " | New Fuzzers: %d"
            
        

    banner_messages = [GREEN +"********* Mutiny Fuzzer + Gluttony" + PURPLE + " <3 " + GREEN + "**********",CYAN  \
                           + "jaspadar@cisco.com" + \
                           GREEN + " && " \
                           + PURPLE + \
                          "liwyatt@cisco.com %s"+CLEAR+"|",
                           GREEN +("*"*output_width)
    ]
    
    dancers = [ "<(^_^)>", "(>-_-)>","(>?_?<)", "<('_-<)", "\\(^_^)/","/(v'v)\\","Q('-'Q)"]

    last_crash_time = "Never" 
    last_queue_time = "Never"
    start_time = datetime.datetime.now()
    current_time = datetime.datetime.now()

    refreshrate = 1

    old_stat_buf = []
    old_fuzzer_buf = [] 
    stat_buffer_list = []
    stat_buffer_layout = ["crash_count","fuzzer_count","processed_count","new_count"] 
    fuzzer_buffer_list = []
    fuzzer_buffer_layout = ["curr_fuzzer","curr_seed","curr_msg","curr_submsg","old_seed","lowerbound","upperbound"]
    last_crash_time = []
    last_queue_time = []

    for i in range(0,instance_count+1):
        stat_buffer_list.append([0,0,0,0])
        fuzzer_buffer_list.append(["",0,0,0,0,0,0])
        old_fuzzer_buf.append("")
        old_stat_buf.append("")
        last_crash_time.append("")
        last_queue_time.append("")

    prevbuf = ""
    banner_buf = ""
    log_buf = "" 

    rows, columns = os.popen('stty size', 'r').read().split()
    height = int(rows)
    width = int(columns)
    old_width = width
    old_height = height

    sys.__stdout__.write("\n"*height) 
    sys.__stdout__.write("\033[0;0H")
    banner_buf = "\n".join(banner_messages) + "\n"
    baseline_newline_count = banner_buf.count("\n")+1 
    sys.__stdout__.write(banner_buf%dancers[0])
    sys.__stdout__.flush()
    autorefresh = True

    fuzzer_stat_list = []
    
    while not kill_switch.is_set():
        try:
            current_new_line_count = baseline_newline_count
            current_time = datetime.datetime.now()
            autorefresh = str(current_time).split(".")[0].endswith("0")
            buf = ""
            rows, columns = os.popen('stty size', 'r').read().split()
            height = int(rows)
            width = int(columns)

            dancer = dancers[current_time.second%len(dancers)]

            if width != old_width or height != old_height or autorefresh:
                sys.__stdout__.write("\033[0;0H")
                banner_buf = "\n".join(banner_messages) + "\n"
                baseline_newline_count = banner_buf.count("\n")+1 
                sys.__stdout__.write(banner_buf%dancer)
                sys.__stdout__.flush()

            row_count = 0
            rows_left = 0
                    
            while not inp_queue.empty():
                inp_tuple = inp_queue.get()
                if len(inp_tuple) > 4:
                    continue 
                try:
                    inp,inp_type,color,thread_num = inp_tuple
                except:
                    continue

                if color in color_test:
                    inp=("%s%s%s" % (color,str(inp),CLEAR))

                if inp_type == "fuzzer":
                    fuzzer_log_messages.append((inp,thread_num))
                    update_fuzzer_log_messages = True

                elif inp_type == "stats":
                    stat_buffer = stat_buffer_list[thread_num]                       
                    # stat_buffer_layout = ["crash_count","fuzzer_count","processed_count","new_count"] 
                    old_crash_count = stat_buffer[0]
                    old_fuzzer_count = stat_buffer[1] 

                    try:
                        if int(inp[0]) >= 0:
                            # crash_count
                            stat_buffer[0] = int(inp[0])  

                        if int(inp[1]) >= 0:
                            # fuzzer_count
                            stat_buffer[1] = int(inp[1])

                        if stat_buffer[0] > old_crash_count:
                            last_crash_time[thread_num] = current_time 

                        if stat_buffer[1] > old_fuzzer_count:
                            last_queue_time[thread_num] = current_time

                        if int(inp[2]) >= 0:
                            # processed_count 
                            stat_buffer[2] = int(inp[2])

                        if int(inp[3]) >= 0:
                            # new_count
                            stat_buffer[3] = int(inp[3])
                        
                    except Exception as e:
                        oops()
                        continue

                elif inp_type == "curr_fuzzer":
                    fuzzer_buffer = fuzzer_buffer_list[int(thread_num)]  
                    #fuzzer_buffer_layout = [ "curr_fuzzer", "curr_seed","curr_msg","curr_submsg","old_seed","lowerbound","upperbound" ]
                    #                              0              1           2          3            4           5             6   
                    try:
                        curr_fuzzer,lowerbound,upperbound = inp
                    except Exception as e:
                        print e
                        continue

                    fuzzer_buffer[0] = curr_fuzzer
                    fuzzer_buffer[5] = lowerbound
                    fuzzer_buffer[6] = upperbound

                elif inp_type == "curr_msg":
                    fuzzer_buffer = fuzzer_buffer_list[int(thread_num)]  
                    try:
                        if fuzzer_buffer[1]: # curr_seed
                            fuzzer_buffer[4] = fuzzer_buffer[1] # old_seed = curr_seed
                        curr_seed,curr_msg,curr_submsg = filter(None,inp.split(",")) 
                        fuzzer_buffer[1] = int(curr_seed)
                        fuzzer_buffer[2] = int(curr_msg)
                        fuzzer_buffer[3] = int(curr_submsg)
                        
                    except:
                        continue

                else:
                    continue

            
            runtime = str(current_time - start_time).split(".")[0] 
            for i in range(0,instance_count):

                if fuzz_flag_list[i].is_set(): 
                    run_status = GREEN + "(Fuzzing)" + CLEAR
                else:
                    run_status = YELLOW + "(Paused)" + CLEAR

                fuzzer_buf = ""
                fuzzer_buf+=CYAN + ("*"*20) + ("Thread-%d"%i) + ("*"*20) + "\n" + CLEAR

                # update time differences
                try:
                    crash_diff = str(current_time - last_crash_time[i]).split(".")[0] 
                except:
                    crash_diff = "Never"
                try:
                    queue_diff = str(current_time - last_queue_time[i]).split(".")[0]
                except:
                    queue_diff = "Never"


                crash_count, fuzzer_count, processed_count, new_count = stat_buffer_list[i]
                stat_buf = stat_messages % (runtime,run_status,\
                                           crash_count,crash_diff,\
                                           fuzzer_count,queue_diff,\
                                           processed_count,new_count)

                stat_buf+="\n"

                if old_stat_buf[i] != stat_buf or width != old_width or old_height != height or autorefresh:
                    sys.__stdout__.write("\033[%d;1H"%current_new_line_count) 
                    sys.__stdout__.write(" "*(stat_buf.count('\n') * width)) 
                    sys.__stdout__.write("\033[%d;1H"%current_new_line_count) 
                    sys.__stdout__.write(stat_buf) 
                    old_stat_buf[i] = stat_buf

                current_new_line_count += stat_buf.count("\n")

                curr_fuzzer, curr_seed, curr_msg, curr_submsg, old_seed, lowerbound, upperbound = fuzzer_buffer_list[i]

                curr_fuzzer_dir = "/".join(curr_fuzzer.split("/")[:-1])
                #fuzzer_buf+=CYAN + ("*"*21) + "Stats" + ("*"*22) + "\n" + CLEAR
                fuzzer_buf+=" Current Fuzzer : " + curr_fuzzer_dir + "\n" 
                fuzzer_buf+= (" "*18) + os.path.basename(curr_fuzzer) + "\n"
                fuzzer_buf+=" Current Seed   : "  

                if fuzz_flag_list[i].is_set():
                    fuzzer_buf+=GREEN    
                else:
                    fuzzer_buf+=YELLOW
                 
                fuzzer_buf+="%08d"%curr_seed + " %s| Msg(%d.%d)" %(CLEAR,curr_msg,curr_submsg) +  "\n"
                fuzzer_buf+=" SeedRange      : [%d,%d]\n"%(lowerbound,upperbound)
                fuzzer_buf+=PURPLE + ("*"*output_width) + "\n" + CLEAR
        
                if old_fuzzer_buf[i] != fuzzer_buf or width != old_width or old_height != height or autorefresh:
                    sys.__stdout__.write("\033[%d;1H"%current_new_line_count) 
                    sys.__stdout__.write(" "*(fuzzer_buf.count("\n")* width)) 
                    sys.__stdout__.write("\033[%d;1H"%current_new_line_count) 
                    sys.__stdout__.write(fuzzer_buf) 
                    old_fuzzer_buf[i] = fuzzer_buf

                current_new_line_count += fuzzer_buf.count("\n")
            
            fuzzer_log_limit = height - (current_new_line_count+1)  
            log_count = 0
            cur_log_len = len(fuzzer_log_messages)
            
            if update_fuzzer_log_messages or old_width != width or old_height != height or autorefresh: 
                log_buf = "" 
                if cur_log_len >= fuzzer_log_limit: 
                    log_count = fuzzer_log_limit
                else:
                    log_count = cur_log_len 
                #print "%d, %d, %d"%(fuzzer_log_limit,log_count,cur_log_len)
                while log_count > 0: 
                    if cur_log_len >= fuzzer_log_limit: 
                        m,thread = fuzzer_log_messages[-1*(fuzzer_log_limit - (fuzzer_log_limit - log_count))]
                    else:
                        m,thread = fuzzer_log_messages[(cur_log_len - log_count)]

                    if thread > 0:
                        try:
                            m = "T%d> %s"%(thread,m)
                        except:
                            m = "T%s> %s"%(thread,m)
                     
                    if len(m) > width: 
                        m = m[:width-4] + "..."

                    if m:
                        log_buf+=(m+"\n")
                        log_count-=1

                #if cur_log_count > fuzzer_log_limit:
                #    fuzzer_log_messages = fuzzer_log_messages[(-1*fuzzer_log_limit)-1:]

                update_fuzzer_log_messages = False

                sys.__stdout__.write("\033[%d;1H"%current_new_line_count) 
                sys.__stdout__.write(" "*((height - current_new_line_count) * width)) 
                sys.__stdout__.write("\033[%d;1H"%current_new_line_count) 
                sys.__stdout__.write(log_buf) 

            current_new_line_count += len(fuzzer_log_messages)

            sys.__stdout__.write("\033[%d;1H"%current_new_line_count) 

            if current_new_line_count < height: 
                sys.__stdout__.write(" "*( (height - current_new_line_count) * width)) 
                sys.__stdout__.write("\033[%d;1H"%current_new_line_count) 
                sys.__stdout__.write(PURPLE + ("*"*output_width) + CLEAR )

            sys.__stdout__.flush()
            time.sleep(refreshrate)
             
            prevbuf = banner_buf + stat_buf + fuzzer_buf + log_buf 
            old_width = width
            old_height = height

        except KeyboardInterrupt:
            sys.__stdout__.write("\033[%d;1H"%height) 
            sys.__stdout__.write(GREEN + "\n[v.v] Ctrl+C => cleaning up....\n" + CLEAR)
            sys.__stdout__.flush()
            kill_switch.set()
            break
        except Exception as e:
            oops()

    # would need to maintain entire log for this to be useful...
    if len(fuzzer_log_messages):
        with open(".feedback_log.txt","w") as f:
            f.write(stat_buf) 
            f.write(fuzzer_buf) 
            for m,thread in fuzzer_log_messages:
                f.write("T%s-%s\n"%(thread,m)) 

    #sys.__stdout__.write(GREEN + "\n[*.*] print_thread cleaned up\n" + CLEAR)
    #sys.__stdout__.flush()
            
 
def oops():
    import traceback
    exc_type, exc_value, exc_traceback = sys.exc_info()
    sys.__stdout__.write("*** print_exception:")
    traceback.print_exception(exc_type, exc_value, exc_traceback,
                              limit=4, file=sys.stdout)
    sys.__stdout__.flush()


if __name__ == "__main__":
    with open("fuzzer_log.txt",'a') as logger:
        main(logger)

