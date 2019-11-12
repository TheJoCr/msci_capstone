import pcapy


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
def print_packet(hdr, data):

  print data


#collect 10 packets then stop
packet_limit = -1
pc.loop(packet_limit, print_packet)
