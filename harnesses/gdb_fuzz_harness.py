import subprocess
import datetime
import socket
import sys
import gdb

from time import sleep

my_stop_request = False
thread_list = []

def thread_handler(event):
    global thread_list
    #if event.inferior_thread.ptid !=
    #thread_list.append(event.inferior_thread.ptid[1])
    # ptid = (parent, child, ???) tuple 
    

def exit_handler(event):
    global my_stop_request

    # ugh, asan shit goes here...
    if my_stop_request:
        my_stop_request = False
        return
    
    try:
        if event.exit_code == 0x1:
            gdb.write("Hit exit handler!")    
            gdb.execute("kill")
            gdb.execute("run")
    except:
        pass


    '''
    has_threads = [ inferior.num for inferior in gdb.inferiors() if inferior.threads() ]
    if has_threads:
        has_threads.sort()
        gdb.execute("inferior %d" % has_threads[0])
        my_stop_request = True
    else:
        gdb.execute("run")
    '''

def stop_handler(event):
    global my_stop_request

    if isinstance(event, gdb.SignalEvent):
        output("\n[^_^] SIG %s\n"%event.stop_signal)
        # or "ERROR: AddressSanitizer" in resp:
        if event.stop_signal == "SIGSEGV":
            crash_handling_actions(event)
            #test = gdb.inferiors()
            # test.inferior...
            #output(gdb.execute("!ls -l /proc/%d/fd"%test.inferior))
            gdb.execute("kill") 
            #renew_breakpoints(True)
            gdb.execute("run")            
        elif event.stop_signal == "SIGABRT":
            output("asdf")
            # check if we're dealing with asan.
            output(gdb)
            backtrace = gdb.execute("bt 20",False,True)
            output(backtrace)
            if "asan" in backtrace: # unwind till we're outside of asan again
                frame = gdb.selected_frame()
                output(frame)
                for line in backtrace.split("\n"):
                    if "raise" in line:
                        frame = frame.older()
                        continue 
                    if "abort" in line:
                        frame = frame.older()
                        continue
                    if "libasan" in line:
                        frame = frame.older()
                        continue
                    output("exiting on frame: %s\n"%line)
                    break
            crash_handling_actions(event,frame)
            gdb.execute("kill")
            #renew_breakpoints(True)
            gdb.execute("run")
        elif event.stop_signal == "SIGTERM":
            # kick the process
            gdb.execute("kill")
            #renew_breakpoints(True)
            gdb.execute("run")            
        
        elif event.stop_signal == "SIGINT":
            gdb.execute("info thread")
            gdb.execute("bt")
        elif event.stop_signal == "SIGPIPE":
            gdb.execute("continue")
        elif event.stop_signal == "SIGTRAP":
            output("Hit sigtrap!\n")
            pass 
        else:
            output("uhhh?")
        

    elif isinstance(event, gdb.BreakpointEvent):
        pass

    elif my_stop_request:
        my_stop_request = False
        gdb.execute("continue")   

def crash_handling_actions(event,inp_frame=None):
    global fuzzer_sock
    frame = gdb.selected_frame()
    if inp_frame!=None:
        frame = inp_frame 
        inp_frame.select()

    try:
        context = gdb.execute("context",False,True)
    except:
        context = gdb.execute("info regs",False,True)
        context += "***********************\n"
        context += gdb.execute("x/10i $pc",False,True)
        context += "***********************\n"
        context += gdb.execute("bt",False,True)

    result = "[^_^] Got a crash! %s\n" % (event.stop_signal) 
    crash_log = result + context
    output(crash_log) 

    pc = frame.read_register("pc")
    curr_time = str(datetime.datetime.now())
    curr_time = curr_time.replace(" ","_").replace(":","_").replace(".","_").replace("-","_")
    filename = "crashes/%s_%s_0x%lx.txt"%(event.stop_signal,curr_time,pc)
    output("writing to %s\n"%filename)
    with open(filename,"wb") as f:
        f.write(crash_log)

    if fuzzer_sock:
        try:
            output("Sending crashlog! (0x%lx) bytes\n"%len(crash_log))
            fuzzer_sock.send(crash_log)
        except Exception as e:
            try:
                fuzzer_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                fuzzer_sock.connect((fuzzer_ip,fuzzer_port))
                fuzzer_sock.send(crash_log)
                fuzzer_sock.close()
            except Exception as e:
                print "[x.x] couldn't connect to fuzzer to report, dumping to %s only!"%filename
                print e
    #except Exception as e:
    #    output(e)   
    #    raise


class AddressBase(gdb.Command):

    def __init__(self,*args,**kw):
        self.cmdline = "baseaddr"
        self.args = "<address>"
        super(AddressBase,self).__init__(self.cmdline,\
                                         gdb.COMMAND_SUPPORT,\
                                         gdb.COMPLETE_NONE,False) 
    def invoke(self,arg,from_tty):
        self.address_map = gdb.execute("info proc map",False,True) 
        try:
            query_address = gdb.parse_and_eval(arg)
        except:
            try:
                query_address = gdb.selected_frame().read_register(arg)
            except:
                gdb.write("[x.x] Usage: %s %s"%(self.cmdline,self.args))
                return

        ret = "[x.x] Not able to find bounds of given address!\n"
        for line in self.address_map.split("\n"):
            if "0x" in line:
                address_region = line.split(None)
                lbound = int(address_region[0],16)
                rbound = int(address_region[1],16)
                #gdb.write("L:0x%lx-R:0x%lx | 0x%lx (%s,%s)\n"%(lbound,rbound,query_address,lbound<=query_address,rbound>=query_address))
                if query_address >= lbound and query_address <= rbound:
                    ret = line + "\n" 
                    break
        gdb.write(ret)


# Avoid a bug that we've already found.
class RestartPoint(gdb.Breakpoint):
    def __init__(self,addr):
        try:
            _addr = "*0x%lx"%addr
        except:
            _addr = "*%s"%str(gdb.parse_and_eval(addr)).split(" ")[0]

        output("[!.!] Restart breakpoint on %s\n"%_addr)
        gdb.Breakpoint.__init__(self,"%s"%_addr,internal=True)
        self.silent = False 

    def stop(self):
        cl = gdb.selected_frame().read_register("cl")
        if cl != 0x40:
            gdb.execute("set $cl=0x40")
        return False

# Example breakpoint for when looking to place inside a library.
# On hit, places a RestartPoint at the given $pc+0x22e
class StagingBreak(gdb.Breakpoint):
    def __init__(self):
        gdb.Breakpoint.__init__(self,\
                                "boop",\
                                internal=True,temporary=True)
        self.silent = True
        self.hit = False
        
    def stop(self):
        global internal_breakpoints
        if not self.hit: 
            internal_breakpoints.append(RestartPoint("$pc+0x22E"))
            self.hit = True
        return False

# Example breakpoint for avoiding a useles overlap Strcpy, since ASAN will normally abort.
class OverlapStrcpyBreak(gdb.Breakpoint):
    def __init__(self):
        # lol, need the "-0x0" or else it gets placed at +0x4... 
        gdb.Breakpoint.__init__(self, "*strcpy-0x0", internal=True)
        self.silent = True

    def stop(self):
        backtrace = gdb.execute("bt",False,True).split("\n")
        if "targetFunc" in str(backtrace):
            strlen = int(gdb.execute("call (int)strlen($rsi)",False,True).split("=")[1],16)
            output("calling memove 0x%lx"%strlen)
            gdb.execute("call (void *)memmove($rdi,$rsi,0x%x)"%strlen) 
            gdb.execute("set $pc=*(long *)$sp")
            gdb.execute("set $sp=($sp+0x8)")
        return False

def output(msg):
    sys.__stdout__.write(str(msg))
    sys.__stdout__.flush()

def renew_breakpoints(delonly=False):
    global internal_breakpoints
    for b in internal_breakpoints:
        b.delete()

    if not delonly:
        internal_breakpoints = [ StagingBreak(), OverlapStrcpyBreak()]
    

fuzzer_ip = "127.0.0.1"
fuzzer_port = 60000 
fuzzer_sock = None
connected = False

try:
    os.mkdir('crashes')
except:
    pass

fuzzer_sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

gdb.events.exited.connect(exit_handler)
gdb.events.stop.connect(stop_handler)
#gdb.events.new_thread.connect(thread_handler)

gdb.execute("set env ASAN_OPTIONS=abort_on_error=1,detect_leaks=0")
gdb.execute("handle SIGPIPE nostop noprint nopass")
gdb.execute("set history save on")
gdb.execute("set history filename ~/.gdb_history")
gdb.execute("set breakpoint pending on")
AddressBase()

# dealing with problem code flows...
#internal_breakpoints = [ StagingBreak(), OverlapStrcpyBreak()]
gdb.execute("run")
# hit breakpoint...
output('[z.z] Fuzzer harness running....\n')

