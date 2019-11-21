import pcapy
from impacket.ImpactDecoder import EthDecoder

#Prints out all devices that we can listen to
print(pcapy.findalldevs())

max_bytes = 1024
promis = False
timeout = 100

#open a live capture
pc = pcapy.open_live("eth0", max_bytes, promis, timeout)

#need to figure out how to filter by HTTP
pc.setfilter('port 80')

#print the packets
def print_packet(packet_header, packet_data):

  decoded_packet = EthDecoder().decode(packet_data)
  print decoded_packet


#collect unlimited packets
packet_limit = -1
pc.loop(packet_limit, print_packet)
