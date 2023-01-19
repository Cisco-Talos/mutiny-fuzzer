#!/usr/bin/python

from scapy.all import *
import sys


dstMac = "\xff\xff\xff\xff\xff\xff"
srcMac = "\xaa\xaa\xaa\xaa\xaa\xaa"
L3type = "\x08\x00"
headerlen = "\x45"

def usage():
    print("Usage: ./%s <pcapfile>" % sys.argv[0])    
    exit()

def main():
    nulls = sys.argv[1]   
    denulled = PacketList()
    
    print("Denulling pcap: %s" % nulls)
    try:
        nulled = rdpcap(nulls)
    except:
        usage()
    
    for packet in nulled:
        denulled.append(Ether(srcMac + dstMac + L3type)/TCP(str(packet)[4:])) 
    print(denulled)
    
    wrpcap("denulled_%s" % sys.argv[1], denulled)


if __name__ == "__main__":
    main()
