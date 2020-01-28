#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http

iface ="eth0"

#sniffing the packet, false to not buffer the sniffed packet
#prn for giving the call back function whenever the packet is captured
def sniff(iface):
    scapy.sniff(iface=iface, store=False, prn=process_packet)

#scan the packet by layers
def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("Http Request host:" + packet[http.HTTPRequest].Host + ", Path: " + packet[http.HTTPRequest].Path)
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
sniff(iface)
