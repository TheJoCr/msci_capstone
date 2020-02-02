#include <stdio.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* to parse Ethernet headers. */
#include <netinet/ip.h> /* to parse IP headers. */
#include <netinet/tcp.h> /* to parse TCP headers. */

// do somthing with the packet
void getHTTPRequest(u_char *data, const struct pcap_pkthdr* header, const u_char* packet)
{
	struct ether_header *ether;
	struct ip *ip;
	struct tcphdr *tcp;

	/////////
	// ETH //
	/////////
	
	// Parse Ethernet header, skip those bytes.
	ether = (struct ether_header*) packet;
	int ether_header_len = sizeof(struct ether_header); // constant size
	packet += ether_header_len;

	/////////
	// IP  //
	/////////
	
	// Parse IP Header, skip those bytes
	ip = (struct ip*) packet;
	int ip_header_len = ip->ip_hl * 4; 
	packet += ip_header_len;
	
	// Get some of the IP info
	in_addr source_ip = ip->ip_src;
	in_addr dest_ip = ip->ip_dst;

	// Convert that to strings
	char source_ip_str[INET_ADDRSTRLEN];
	char dest_ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(source_ip), source_ip_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(dest_ip),   dest_ip_str,   INET_ADDRSTRLEN);

	/////////
	// TCP //
	/////////
	
	// Parse TCP header, skip those bytes
	tcp = (struct tcphdr*) packet;
	int tcp_data_offset = tcp->doff * 4; 
	packet += tcp_data_offset;

	// Get a bit of TCP info. Needs to be converted from network endianness
	// to local.
	unsigned short source_port = ntohs( tcp->th_sport );
	unsigned short dest_port = ntohs( tcp->th_dport );
	unsigned int seq_num = ntohl( tcp->th_seq );
	unsigned int ack_num = ntohl( tcp->th_ack );

	/////////
	// OUT //
	/////////

	printf("Packet from %s:%u to %s:%u (seq: %u, ack: %u)\n", 
			source_ip_str, source_port,
			dest_ip_str, dest_port,
			seq_num, ack_num);

	int body_size = header->caplen - ether_header_len - ip_header_len - tcp_data_offset;

	if (body_size != 0) {
		printf("Body (%d bytes):\n", body_size);
		for( int i = 0; i < body_size; i++ ) {
			printf("%c", packet[i] );
		}
	}
}



int main(int argc, char *argv[])
{
	pcap_t *handle;			// pcap session handle
	char *dev;			// the device
	char errbuf[PCAP_ERRBUF_SIZE];	// error string
	struct pcap_pkthdr header;	// the packet header
	const u_char *packet;		// the packet
	char filter[] = "port 8000";    // the filter
	struct bpf_program fp;		// compiled filter expression
	bpf_u_int32 mask;		// the netmask of the sniffing device
	bpf_u_int32 net;		// the ip of sniffing device

	// assign the device
	// dev = pcap_lookupdev(errbuf);
	dev = (char*) "lo";
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	
	//get the netmask
	pcap_lookupnet(dev, &net, &mask, errbuf);

	// open the packet capture session
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	// compile the filter
	pcap_compile(handle, &fp, filter, 0, net);

	// set the filter
	pcap_setfilter(handle, &fp);

	//loop 10 times using the above function
	pcap_loop(handle, 20, getHTTPRequest, NULL);	

	
	// close
	pcap_close(handle);
	return(0);
}
