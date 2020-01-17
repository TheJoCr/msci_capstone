#include <stdio.h>
#include <pcap.h>

static int pktCount = 0;

// do somthing with the packet
void getHTTPRequest(u_char *data, const struct pcap_pkthdr* header, const u_char* packet)
{
	//print out when a packet is received for now.
	++pktCount;	
	printf("packet captured of length: %d\n", header->len);
}



int main(int argc, char *argv[])
{
	pcap_t *handle;			// pcap session handle
	char *dev;			// the device
	char errbuf[PCAP_ERRBUF_SIZE];	// error string
	struct pcap_pkthdr header;	// the packet header
	const u_char *packet;		// the packet

	// assign the device
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}

	// open the packet capture session
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	//loop 10 times using the above function
	pcap_loop(handle, 10, getHTTPRequest, NULL);	

	
	// close
	pcap_close(handle);
	return(0);
}
