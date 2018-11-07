#!/usr/bin/env python2
import sys
import os

def main(target_dir):
    
    try:
        os.mkdir(os.path.join(target_dir,'sorted'))
    except Exception as e:
        print e
        pass

    crash_list = []
    for f in os.listdir(target_dir):
        target_file = os.path.join(os.path.abspath(target_dir),f)

        if not f.startswith("harness.log"): 
            continue

        crashInfo = parse_file(os.path.abspath(target_file)) 
        if crashInfo == "":
            print "Unable to classify %s, please investigate manually"%target_file
            continue
        try:
            crashDump,crashType,crashAddr = crashInfo
        except Exception as e:
            print e
            print "Unable to classify %s, please investigate manually"%target_file
            continue

        crash_dir = os.path.join(target_dir,crashType)
        addr_dir = os.path.join(crash_dir,crashAddr)

        try:
            os.mkdir(crash_dir) 
        except:
            pass

        try:
            os.mkdir(addr_dir) 
        except:
            try:
                # name too long?.
                addr_dir = addr_dir[0:255]
                os.mkdir(addr_dir) 
                #print "Unable to generate folder name (len:%d): %s"%(len(addr_dir),addr_dir)
            except:
                pass
        try:
            dst = os.path.join(addr_dir,f)
            with open(dst,"wb") as d:
                d.write(crashDump)
        except Exception as e:
            dst = os.path.join(addr_dir[0:255],f)
            with open(dst,"wb") as d:
                d.write(crashDump)
        
        if addr_dir not in crash_list:
            print addr_dir
            crash_list.append(addr_dir)

        # move to sorted pile
        try:
            os.rename(target_file,os.path.join(target_dir,"sorted",f))
        except:
            os.rename(target_file,os.path.join(target_dir[0:255],"sorted",f))


    print "[^_^] All crashes hopefully sorted!"
            

def parse_file(filename):
    basename = os.path.basename(filename)
    try:
        crashTime = basename.split(".")[2]
    except:
        return ""
    # todo, script correlating mutitrace.txt w/ this.      

    buf = ""
    with open(filename,"rb") as f:
        buf = f.read()
    if len(buf) == 0:
        os.remove(filename)
        print "Deleting empty log"
    
    if buf.find("AddressSanitizer") > 0:
        delim = "Error: AddressSanitizer:"
    else:
        delim = "received signal "

    crashBufLoc = buf.find(delim) + len(delim)  
    #print "Crash Buf loc: 0x%x"%crashBufLoc
    if crashBufLoc == -1:
        print "No crash inside log, deleting"
        os.remove(filename)
        return ""

    buf = buf[crashBufLoc:]

    if buf.find("AddressSanitizer") > 0:
        crashTypeLoc = buf.find(" ")
        crashType = buf[0:crashTypeLoc]  
        crashAddrLoc = buf.find("at pc ")+len("at pc ")
        crashAddrRbound = buf[crashAddrLoc:].find(" ") + crashAddrLoc
        crashAddr = buf[crashAddrLoc:crashAddrRbound]
    else:
        crashTypeLoc = buf.find(",") 
        #print crashTypeLoc
        if crashTypeLoc == -1 or crashTypeLoc > 0x10:
            return ""
        crashType = buf[0:crashTypeLoc]  
    
        crashAddrLoc = buf.find("\nrip  ")+1  
        if crashAddrLoc == -1:
            crashAddrLoc = buf.find("\neip  ")+1  
        if crashAddrLoc == -1:
            crashAddrLoc = buf.find("\npc  ")+1  
        if crashAddrLoc == -1:
            return "" 

        crashAddrLbound = buf[crashAddrLoc:].find("0x") + crashAddrLoc+1
        crashAddrLbound = buf[crashAddrLbound:].find("0x") + crashAddrLbound
        crashAddrRbound = buf[crashAddrLbound:].find("\n") + crashAddrLbound 
        crashAddr = buf[crashAddrLbound:crashAddrRbound].replace(" ","_") 
    #print buf[crashAddrLbound:crashAddrLbound+0x40]
    #print "crashAddrBounds: %d-%d" % (crashAddrLbound,crashAddrRbound)
    #print "crashAddr: %s" % crashAddr
    return buf,crashType,crashAddr 
    

def usage():
    if "--help" in sys.argv:
        print "Point this thing to a directory of harness dumps\n" +\
              "and it'll hopefully classify everything/sort it\n"  +\
              "by the crash type and address, along with cleaning\n"+\
              "out all the trash loggng info\n"
    print "[?.?] %s <target_dir>" % sys.argv[0]

if __name__ == "__main__":
    if "--help" in sys.argv:
        usage() 
        sys.exit()
    try:
        target_dir = sys.argv[1]
    except:
        usage()
        sys.exit() 
    main(target_dir)
