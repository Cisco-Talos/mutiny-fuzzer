#!/usr/bin/env python2
import random
import socket
import struct
import time
import sys

INIT_NEW_TRACE       = "\x01\x00\x00\x00\x00"
INIT_PREVIOUS_TRACE  = "\x02\x00\x00\x00\x00"
FUZZ_CASE            = "\x03\x00\x00\x00\x00"
EOFUZZ_CASE          = "\x04\x00\x00\x00\x00"
CLEANUP_MSG          = "\x05\x00\x00\x00\x00"
START_FEEDBACK_MSG   = "\x06\x00\x00\x00\x00"
STOP_FEEDBACK_MSG    = "\x07\x00\x00\x00\x00"
HEARTBEAT            = "\x00\x00\x00\x00\x00"


DEFAULT_PORT = 61601

'''
// ~~~~~~~ Start Inbound socket message definitions and utilities ~~~~~~~ 
//-------------------------------------------------------------------- 
// 0x80 | ORelay->Fuzzer    | Mutitrace: Yo, that testcase was cool. 
//      | (no contents)     | Fuzzer: Okay, saving it and adding to the queue. 
// 
// 0x84 | ORelay->Fuzzer    | Mutitrace: Sending fuzzer my stuff. 
//      | (no contents)     | Fuzzer: okay, listening for stuff.
//
// 0x8F | ORelay->Fuzzer    | Mutitrace: prog pooped/detected a crash, save that. 
//      | (no contents)     | Fuzzer: Okay, saving it. 
//-------------------------------------------------------------------- //
'''

opcode_dict = {
    0x80:"save_queue",
    0x84:"receive_shutdown_data",
    0x8F:"save_crash",
    0xF0:"",
}

# for random choice purposes
opcode_list = list(opcode_dict)

def main():
    if len(sys.argv) < 2: 
        help()
        sys.exit()

    ip = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except:
        port = DEFAULT_PORT
        pass  
    
    sock = -1
    while sock == -1: 
        time.sleep(2)
        try:
            sock = init_feedback_socket(ip,port)
        except KeyboardInterrupt:
            print "[^.^] exiting!"
            sys.exit()

        # at this point, send packets when needed:
        # <byte size><word len><len bytes> 
        if sock and sock != -1:
            test_feedback(sock)
    
    
def test_feedback(inp_sock):    
    # sleep random time and send random message.
    
    inp_sock.settimeout(.1)
    while True:
        time.sleep(random.randint(0,10))
        #opcode = random.choice(opcode_list) 
        opcode = 0x80
        msg = gen_msg(opcode,"") 
        print "[^_^] sending 0x%x opcode!"%opcode
        inp_sock.send(msg)
        try:
            response = inp_sock.recv(66535)
            if response:
                print "[O.O] Got 0x%x bytes back!" % len(response)
                print repr(response)
                response = ""
        except:   
            pass
        
         
def gen_msg(msgnum,msg=""):
    ret = ""
    ret += chr(msgnum) 
    ret += struct.pack("<I",len(msg))
    ret += msg
    return ret

def init_feedback_socket(ip,port=DEFAULT_PORT):
    feedback_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        feedback_socket.connect((ip,port)) 
        print "[^_^] Connected to %s:%d"%(ip,port)
    except:
        print "[x.x] Could not connect to %s:%d"%(ip,port)
        return -1
     
    # init/handshake, lol.
    feedback_socket.send("boop")
    tmp = feedback_socket.recv(4)
    if "doop" not in tmp:
        print "[x.x] Invalid handshake Received: %s"%repr(tmp)
        print "[>.>] (expecting 'doop')"
        return -1 
    
    return feedback_socket
    


def help():
    print "[^_^] %s <feedback_ip> <feedback_port>"% sys.argv[0]


if __name__ == "__main__":
    main()




