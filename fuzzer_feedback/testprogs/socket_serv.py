#!/usr/bin/env python
import socket
import datetime
import time

def main():
    
    while True:
        sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("127.0.1",9999))
        sock.listen(5)

        fuzzer_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        fuzzer_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        fuzzer_sock.bind(("127.0.1",61601))
        fuzzer_sock.listen(1)

        fcli_sock,_ = fuzzer_sock.accept()
        print "[^_^] fzzer connection %s:%d"%_
        init_str = fcli_sock.recv(4)
        if init_str != "boop":
            print "[?.?] Bad init recv'ed: %s" % repr(init_str)
            return
        else:
            print "[^^] got init"
        
        fcli_sock.send("doop")
        time.sleep(.1)
        fcli_sock.send("\x01\x07\x00\x00\x00<(^_^)>")

        cli_sock,cli_addr = sock.accept()
        msg = cli_sock.recv(2048)
        cli_sock.send("herp")
        print "[^_^] %s Recieved @ %s" % (msg,str(datetime.datetime.now()))

        fcli_sock.send("\x02\x07\x00\x00\x00<(^_^)>")
        fuzzer_sock.settimeout(2)

        while True:
            try:
                msg = fuzzer_sock.recv(2048)
                if len(msg) > 0:
                    print "+[^_^] %s Recieved @ %s" % (msg,str(datetime.datetime.now()))
                else:
                    break
            except:
                break

        cli_sock.close()
        fcli_sock.close()
    
        sock.close()
        fuzzer_sock.close()
    
    


if __name__ == "__main__":
    main()
