
//																									//
//												TIDY UP CODE										//
//																									//
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "postgrabber.h"

void packet_handler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet) {
	struct ether_header *eth_header;
	const struct ip_packet *ip;
	eth_header = (struct ether_header *) packet;

	char *payload;

	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP)
	{
		ip = (struct ip_packet*)(packet + ethernet_header_length);

		int ihl = getipheader_len(packet);
		u_char protocol = *(ip_header + 9);
		char *ip_src = inet_ntoa(ip->ip_src);
		char *ip_dst = inet_ntoa(ip->ip_dst);
		
		if(protocol != IPPROTO_TCP){
			return;
		}

		getpayload(packet, header);

	}
}

int main(int argc, char const *argv[])
{	
	char ip[13];
	char *device;
	pcap_t *handle;
	char error_buffer[PCAP_ERRBUF_SIZE];
	struct in_addr address;
	bpf_u_int32 ip_raw;
	struct pcap_pkthdr packet_header;
	const u_char *packet;

	//TODO: Change these to run from cmd args
	int snapshot_len = 1028;
	int promiscuous = 0;
	int timeout = 1000;

	/* Find a device */
	device = pcap_lookupdev(error_buffer);
	if (device == NULL) {
		fatal("finding a device");
		return 1;
	}

	printf("starting up on %s\n", device);

	handle = pcap_open_live(device, snapshot_len, promiscuous, timeout, error_buffer);

	while(1){
		pcap_loop(handle, 1, packet_handler, NULL);
	}

	return 0;
}