import sys
import argparse
from scapy.all import *

def main():

    if len(sys.argv) < 2:
        sys.argv.append('-h') 

    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="pcap to dump")
    parser.add_argument("-f", "--filename", help="file to write to") 
    args = parser.parse_args()

    pcap = rdpcap(args.pcap)

    try:
        srcPort = pcap[0][TCP].sport
    except:
        srcPort = pcap[0][UDP].sport

    src = ( pcap[0][Ether].src, pcap[0][IP].src, srcPort) 

    retbuff = []
    for packet in pcap:
        # skip packets without data (syn/ack/synack)
        try:
            len(packet[Raw])
        except IndexError:
            continue
            
        tmp = ""
        if isSrc(src,packet): 
            try:
                for byte in str(packet[Raw]):
                    tmp+="\\x0" if ord(byte) <= 0xf else "\\x"  
                    tmp+=hex(ord(byte))[2:] 
            except IndexError:
                pass
            if tmp:
                retbuff.append("send(\"" + tmp + "\")")
        
        #recv(1024) data sent by server, don't really care what it is         
        else: 
            retbuff.append("recv(1024)") if len(packet) < 1024 else retbuff.append("recv(%d)" % len(packet))
    
    if args.filename:
        with open(args.filename,'w') as f: 
            for packet in retbuff:
                f.write(packet + "\n")
    else:
        for packet in retbuff:
            print(packet)
 
def isSrc(srcInfo,packet):   
    # info_tuple[0] = [Ether].src
    # info_tuple[1] = [IP].src
    # info_tuple[2] = [TCP/UDP].sport
    try:
        l4port = packet[TCP].sport
    except:
        l4port = packet[TCP].sport
      
    try:
        if packet[Ether].src == srcInfo[0] and packet[IP].src == srcInfo[1] and l4port == srcInfo[2]: 
            return 1 
    except:
        pass 

    return 0


if __name__ == "__main__":
    main()
