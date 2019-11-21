import pcapy
from struct import *
import socket
import datetime

def main():
    dev = pcapy.findalldevs()[0]
    print("using device: ", dev)
    
    # open device
    max_num_bytes_per_packet = 65536
    promiscious_mode = 1
    timeout_ms = 0
    pc = pcapy.open_live(dev, max_num_bytes_per_packet, promiscious_mode, timeout_ms)
    pc.setfilter('port 80')
    
    # sniffing
    packet_limit = -1
    pc.loop(packet_limit, parse)

def parse(header, packet):
    print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))

    


if __name__ == "__main__":
    main()
