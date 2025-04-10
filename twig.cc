#include <stdlib.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <chrono>
#include "twig-utils.h"
#include <arpa/inet.h>

// Global vars

int debug = 0;
int twig_debug = 0;
int arp_debug = 0;

int fd = 0; // initiate to 0 as stdin file descriptor (if not stdin then it will be changed)

bool byteswap = false;


// Debug function declarations  

void print_ethernet(struct eth_hdr *peh);

void print_UDP(UDP *udp);

void print_TCP(TCP *tcp);

void print_IPv4(IPv4 *ipv4);

void print_Arp(ARP *arp);

void print_ICMP(ICMP *icmp);

u_int16_t byteswap16(u_int16_t val) {
	return (val << 8) | (val >> 8);
};

u_int32_t byteswap32(u_int32_t val) {
	return ((val << 24) & 0xFF000000) | ((val << 8) & 0x00FF0000) | ((val >> 8) & 0x0000FF00) | (val >> 24);
};


// Actual function declaration

u_short IPv4_checksum_maker(u_short *buffer, int size);

// ICMP stuff

void do_ICMP(ICMP_packet *packet, size_t size);

u_short ICMP_checksum_maker(u_short *buffer, int size);

void build_and_send_ICMP(ICMP_packet *packet, size_t size);

// UDP stuff

void do_UDP(UDP_packet *packet, size_t size);

u_short UDP_checksum_maker(u_short *buffer, int size);

void build_and_send_UDP(UDP_packet *packet, size_t size);


/* 
 * the output should be formatted identically to this command:
 *   tshark -T fields -e frame.time_epoch -e frame.cap_len -e frame.len -e eth.dst -e eth.src -e eth.type  -r ping.dmp
 */

int main(int argc, char *argv[])
{
	struct pcap_file_header pfh;
	char *filename;

	/* start with something like this (or use this if you like it) */
	/* i'm using it */
	if (argc == 2 && !(strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) ) {
		filename = argv[1];
	} else if ((argc == 3) && (strcmp(argv[1],"-d") == 0)) {
		debug = 1;
		twig_debug = 1;
		filename = argv[2];
	}
	else if ((argc == 3) && (strcmp(argv[1],"-n") == 0)) {
		filename = argv[2];
	} 
    else if ((argc == 3) && (strcmp(argv[1],"-td") == 0)) {
        twig_debug = 1;
		filename = argv[2];
	}
	else if ((argc == 3) && (strcmp(argv[1],"-a") == 0)) {
		arp_debug = 1;
		filename = argv[2];
 	}
	else if ((argc == 3) && (strcmp(argv[1],"-i") == 0)) {
		std::string ip_addr = argv[2];
		
		// Find the mask if the string is in the right pos
		std::string mask = ip_addr.find("_") ? ip_addr.substr(ip_addr.find("_") + 1) : "";

		ip_addr = ip_addr.substr(0, ip_addr.find("_"));
		ip_addr.at(ip_addr.length() - 1) = '0'; // Set the last octet to 0

		// Hardcoded for this assignment

		std::string temp_filename = ip_addr + "_" + mask + ".dmp";
		filename = strdup(temp_filename.c_str());

		printf("Network address: %s/%s\n", ip_addr.c_str(), mask.c_str());
		printf("Filename: %s\n", filename);
	} else {
		fprintf(stdout,"Usage for normal: %s filename\n", argv[0]);
		fprintf(stdout,"Usage for interface: %s -i [interface]\n", argv[0]);
		fprintf(stdout,"Usage for debug types where -d is for full debug and -dt is for twig debug: %s [-d,-td] filename\n", argv[0]);
		fprintf(stdout,"Usage for ARP cache output: %s -a filename\n", argv[0]);

		exit(99); // a little extreme but i'll allow it
	}

	if (debug) printf("Trying to read from file '%s'\n", filename);

	/* now open the file (or if the filename is "-" make it read from standard input)*/
	if(strcmp(filename, "-") != 0) {
		// fd = open(filename, O_RDWR);
		fd = open(filename, O_RDWR | O_APPEND);
		if(debug) printf("fd: %d\n", fd);
		if (fd < 0) {
			if(debug) printf("fd: %d < 0\n", fd);
			fprintf(stderr, "%s: Permission denied\n", filename); // Doesn't hit on Windows but does on Linux
			exit(1);
		}
	} 


	/* read the pcap_file_header at the beginning of the file, check it, then print as requested */
	int ret = 0;
	ret = read(fd, &pfh, sizeof(pfh));
	if(ret != sizeof(pfh)) {
		fprintf(stderr, "truncated pcap header: only %d bytes\n", ret);
		exit(1);
	}
	if (pfh.magic != PCAP_MAGIC) 
	{
		if(byteswap32(pfh.magic) == PCAP_MAGIC)
		{
			if(debug)
				printf("byte order reversed\n");
			pfh.magic = byteswap32(pfh.magic);
			pfh.version_major = byteswap16(pfh.version_major);
			pfh.version_minor = byteswap16(pfh.version_minor);
			pfh.linktype = byteswap32(pfh.linktype);

			// these aren't used, but i did it just in case
			pfh.thiszone = byteswap32(pfh.thiszone);
			pfh.sigfigs = byteswap32(pfh.sigfigs);
			pfh.snaplen = byteswap32(pfh.snaplen);
			byteswap = true;

			if(debug || twig_debug)
				printf("byte order reversed\n");
			
		}
		else
		{
			fprintf(stderr, "invalid magic number: 0x%08x\n", pfh.magic);
			exit(1);
		}
	}

	if(pfh.version_major != PCAP_VERSION_MAJOR || pfh.version_minor != PCAP_VERSION_MINOR)
	{
		fprintf(stderr, "invalid pcap version: %d.%d\n", pfh.version_major, pfh.version_minor);
		exit(1);
	}


    if(debug) {
        printf("header magic: %08x\n", pfh.magic);
        printf("header version: %d %d\n", pfh.version_major, pfh.version_minor);
        printf("header linktype: %d\n\n", pfh.linktype);
    }

	
	/* create the ARP cache struct */
	ARP_Cache *arp_cache;
	arp_cache = (ARP_Cache *)malloc(sizeof(ARP_Cache)); // Allocate memory for the ARP cache
	if(arp_cache == NULL) {
		perror("malloc failed for ARP_Cache");
		exit(1);
	}
	arp_cache->count = 0; // Initialize the count to 0
	
	if(debug || twig_debug) printf("Created ARP cache struct\n");
	/* now read each packet in the file */
	while (1) {
		char packet_buffer[100000]; // bad boo go away unsafe booos
		
		/* read the pcap_packet_header, then print as requested */
		struct pcap_pkthdr pph;
		ret = read(fd, &pph, sizeof(pph));
		
		if(debug) 
		{
			printf("Packet header read %d bytes\n", ret);
			printf("Read: ");
			for (int i = 0; i < ret; i++) {
				printf("%02d ", ((unsigned char *)&pph)[i]);
			}
			printf("\n");
			fflush(stdout);
		}
		
		if (ret == 0) {
			usleep(3000); // Delay
			continue;
		}
		
		if(ret != sizeof(pph)) {
			fprintf(stderr, "truncated packet header: only %d bytes\n", ret);
			break;
		}
		
		if (byteswap) { // this took me too long to figure this out
			pph.ts_secs = byteswap32(pph.ts_secs);
			pph.ts_usecs = byteswap32(pph.ts_usecs);
			pph.caplen = byteswap32(pph.caplen);
			pph.len = byteswap32(pph.len);
		}
		
		/* then read the packet data that goes with it into a buffer (variable size) */
		// pph.caplen = byteswap32(pph.caplen);

		fflush(stdout);
		ret = read(fd, packet_buffer, pph.caplen);
		
		if(debug) 
		{
			printf("Packet read %d bytes\n", ret);
			fflush(stdout);
			printf("Read: ");
			for (int i = 0; i < ret; i++) {
				printf("%02d ", ((unsigned char *)&pph)[i]);
			}
			printf("\n");
		}
		
		if (ret < static_cast<int>(pph.caplen)) {
			fprintf(stderr, "truncated packet: only %d bytes\n", ret);
			exit(1);
		}

        if(debug) {
            printf("%10d", pph.ts_secs); // i hate cout
            printf(".%06d000\t", pph.ts_usecs);
            printf("%d\t%d\t", pph.caplen, pph.len);
        }
		

		if (pfh.linktype == 1) {
			eth_hdr *eh = (eth_hdr *) packet_buffer;
            if(debug) print_ethernet(eh);
			if(debug) 
				printf("ethernet type: 0x%04x\n", byteswap16(eh->type));

			switch (byteswap16(eh->type))
			{
			case 0x0800: // IPv4
            {
                IPv4 *ip_head = (IPv4 *)(packet_buffer + sizeof(eth_hdr));
				if(debug) print_IPv4(ip_head); // Packet buffer is the start of the packet, so add eth_hdr size to get to the start of the IPv4 header

				
				// Add the source MAC and IP to the ARP cache
				if(debug || twig_debug || arp_debug) printf("Attempting to add to ARP cache\n");
				arp_cache->add_entry(eh->src, ip_head->src);

				if(arp_debug) {
					printf("ARP Cache:\n");
					for(int i = 0; i < arp_cache->count; i++) {
						printf("\tMAC: %02x:%02x:%02x:%02x:%02x:%02x\tIP: %d.%d.%d.%d\n", 
							arp_cache->entries[i].mac[0], arp_cache->entries[i].mac[1], arp_cache->entries[i].mac[2], 
							arp_cache->entries[i].mac[3], arp_cache->entries[i].mac[4], arp_cache->entries[i].mac[5],
							arp_cache->entries[i].ip[0], arp_cache->entries[i].ip[1], arp_cache->entries[i].ip[2], 
							arp_cache->entries[i].ip[3]);
						printf("\tLast seen: %s", ctime(&arp_cache->entries[i].last_seen));
					}
				}
				
                if(ip_head->type == 1) 
                {
					ICMP *icmp = (ICMP *)(packet_buffer + sizeof(eth_hdr) + sizeof(IPv4));
					char* payload = packet_buffer + (sizeof(eth_hdr) + sizeof(IPv4) + sizeof(ICMP));
					size_t size = (pph.caplen - sizeof(eth_hdr) - sizeof(IPv4) - sizeof(ICMP));
					
					ICMP_packet *packet;
					packet = (ICMP_packet *)malloc(sizeof(ICMP_packet)); // Allocate memory for the ICMP packet
					if(packet == NULL) {
						perror("malloc failed for ICMP_packet");
						exit(1);
					}
					memcpy(&packet->phead, &pph, sizeof(pph));
					memcpy(&packet->ehead, eh, sizeof(eth_hdr));
					memcpy(&packet->ip, ip_head, sizeof(IPv4));
					memcpy(&packet->icmp, icmp, sizeof(ICMP));
					memcpy(packet->payload, payload, size);

                    if(twig_debug)
					{
						printf("### We got ourselves an ICMP header ###\n");
						print_ethernet(eh);
						print_IPv4(ip_head);
						print_ICMP(icmp);
						printf("Payload: ");
						// Print the payload for debugging
						for (size_t i = 0; i < size; i++) {
							printf("%02x ", packet->payload[i]);
						}
						printf("\n Of size: %zu\n", size);
					}
                    do_ICMP(packet, size);
                }
				else if (ip_head->type == 0x11) // UDP
				{
					UDP *udp = (UDP *)(packet_buffer + sizeof(eth_hdr) + sizeof(IPv4));
					char* payload = packet_buffer + (sizeof(eth_hdr) + sizeof(IPv4) + sizeof(UDP));
					size_t size = (pph.caplen - sizeof(eth_hdr) - sizeof(IPv4) - sizeof(UDP));
					
					UDP_packet *packet;
					packet = (UDP_packet *)malloc(sizeof(UDP_packet)); // Allocate memory for the ICMP packet
					if(packet == NULL) {
						perror("malloc failed for UDP_packet");
						exit(1);
					}
					memcpy(&packet->phead, &pph, sizeof(pph));
					memcpy(&packet->ehead, eh, sizeof(eth_hdr));
					memcpy(&packet->ip, ip_head, sizeof(IPv4));
					memcpy(&packet->udp, udp, sizeof(UDP));
					memcpy(packet->payload, payload, size);

					if(twig_debug)
					{
						printf("### We got ourselves a UDP header ###\n");
						print_ethernet(eh);
						print_IPv4(ip_head);
						print_UDP(udp);
						printf("Payload: ");
						// Print the payload for debugging
						for (size_t i = 0; i < size; i++) {
							printf("%02x ", packet->payload[i]);
						}
						printf("\n Of size: %zu\n", size);
					}
					do_UDP(packet, size);
				}
				break;
            }
			case 0x0806: // ARP
				if(debug) print_Arp((ARP *)(packet_buffer + sizeof(eth_hdr))); // Packet buffer is the start of the packet, so add eth_hdr size to get to the start of the ARP header
				break;
			default:
				break;
			}
		}
	}
}


/* Function definitions */ 

void print_ethernet(struct eth_hdr *peh) {
	// Had to swap to printf because cout was breaking the output for some reason
	printf("%02x:%02x:%02x:%02x:%02x:%02x\t", peh->dest[0], peh->dest[1], peh->dest[2], peh->dest[3], peh->dest[4], peh->dest[5]);
	printf("%02x:%02x:%02x:%02x:%02x:%02x\t", peh->src[0], peh->src[1], peh->src[2], peh->src[3], peh->src[4], peh->src[5]);
	printf("0x%04x\n", byteswap16(peh->type));
	fflush(stdout);
}

void print_UDP(UDP *udp) {
	printf("\tUDP:\tSport:\t%d\n", byteswap16(udp->sport));
	printf("\t\tDport:\t%d\n", byteswap16(udp->dport));
	printf("\t\tDGlen:\t%d\n", byteswap16(udp->len));
	printf("\t\tCSum:\t%d\n", byteswap16(udp->checksum));
}

void print_TCP(TCP *tcp) {
	printf("\tTCP:\tSport:\t%d\n", byteswap16(tcp->sport));
	printf("\t\tDport:\t%d\n", byteswap16(tcp->dport));

	printf("\t\tFlags:\t%s", (tcp->flags & 0x01 ? "F" : "-"));
	printf("%s", (tcp->flags & 0x02 ? "S" : "-"));
	printf("%s", (tcp->flags & 0x04 ? "R" : "-"));
	printf("%s", (tcp->flags & 0x08 ? "P" : "-"));
	printf("%s", (tcp->flags & 0x10 ? "A" : "-"));
	printf("%s", (tcp->flags & 0x20 ? "U" : "-"));
	printf("\n");

	printf("\t\tSeq:\t%u\n", byteswap32(tcp->seq));
	printf("\t\tACK:\t%u\n", byteswap32(tcp->ack));
	printf("\t\tWin:\t%d\n", byteswap16(tcp->win));
	printf("\t\tCSum:\t%d\n", byteswap16(tcp->csum));
}

void print_IPv4(IPv4 *ipv4) {
	printf("\tIP:\tVers:\t4\n");
	printf("\t\tHlen:\t%d bytes\n", (ipv4->hlen & 0x0F) * 4); // this was also gross
	printf("\t\tSrc:\t%d.%d.%d.%d\t\n", ipv4->src[0], ipv4->src[1], ipv4->src[2], ipv4->src[3]);
	printf("\t\tDest:\t%d.%d.%d.%d\t\n", ipv4->dest[0], ipv4->dest[1], ipv4->dest[2], ipv4->dest[3]);
	printf("\t\tTTL:\t%d\n", ipv4->ttl);
	printf("\t\tFrag Ident:\t%d\n", byteswap16(ipv4->frag_ident));
	
	printf("\t\tFrag Offset:\t%d\n", (byteswap16(ipv4->frag_offset) & 0x1FFF) * 8); // this was gross; i had to look up the offset for the offset

	printf("\t\tFrag DF:\t%s\n", (byteswap16(ipv4->frag_offset) & 0x4000) ? "yes" : "no"); // i haven't had an excuse to use a ? in a while
	printf("\t\tFrag MF:\t%s\n", (byteswap16(ipv4->frag_offset) & 0x2000) ? "yes" : "no");
	printf("\t\tIP CSum:\t%d\n", byteswap16(ipv4->csum));
	if(ipv4->type == 0x06) {
		printf("\t\tType:\t0x%x\t(TCP)\n", ipv4->type);
		print_TCP((TCP *)(ipv4 + 1));
	} else
		printf("\t\tType:\t0x%x\t\n", ipv4->type);
}

void print_Arp(ARP *arp) {
	printf("\tARP:\tHWtype:\t%d\n", byteswap16(arp->htype));
	printf("\t\thlen:\t%d\n", arp->hlen);
	printf("\t\tplen:\t%d\n", arp->plen);
	printf("\t\tOP:\t%d (ARP %s)\n", byteswap16(arp->op), (byteswap16(arp->op) == 1) ? "request" : "reply");
	printf("\t\tHardware:\t%02x:%02x:%02x:%02x:%02x:%02x\n", arp->sha[0], arp->sha[1], arp->sha[2], arp->sha[3], arp->sha[4], arp->sha[5]);
	printf("\t\t\t==>\t%02x:%02x:%02x:%02x:%02x:%02x\n", arp->tha[0], arp->tha[1], arp->tha[2], arp->tha[3], arp->tha[4], arp->tha[5]);
	printf("\t\tProtocol:\t%d.%d.%d.%d\t\n", arp->spa[0], arp->spa[1], arp->spa[2], arp->spa[3]);
	printf("\t\t\t==>\t%d.%d.%d.%d\t\n", arp->tpa[0], arp->tpa[1], arp->tpa[2], arp->tpa[3]);
}

void print_ICMP(ICMP *icmp){
    printf("\tICMP:\tType:\t%d\n", icmp->type);
    printf("\t\tCode:\t%d\n", icmp->code);
    printf("\t\tCSum:\t%d\n", byteswap16(icmp->checksum));
    if (icmp->type == 0 || icmp->type == 8) { // Echo reply or request
        printf("\t\tID:\t%d\n", byteswap16(icmp->id));
        printf("\t\tSeq:\t%d\n", byteswap16(icmp->seq));
    }
}

void do_ICMP(ICMP_packet *packet, size_t size){
	if(twig_debug) printf("Doing ICMP\n");
	// Build the ICMP packet
	ICMP_packet *reply;
	reply = (ICMP_packet *)malloc(sizeof(ICMP_packet)); // Allocate memory for the ICMP packet
	
	if(reply == NULL) {
		perror("malloc failed for ICMP_packet reply");
		exit(1);
	}
	
	memcpy(&reply->icmp, &packet->icmp, sizeof(ICMP)); // Copy the ICMP header from the original packet
	memcpy(&reply->phead.ts_secs, &packet->phead.ts_secs, sizeof(packet->phead.ts_secs)); // Copy the timestamp from the original packet
	memcpy(&reply->phead.ts_usecs, &packet->phead.ts_usecs, sizeof(packet->phead.ts_usecs)); // Copy the timestamp from the original packet
	
	
	if(packet->icmp.type == 8) // We got an echo request (ping), we must reply!!! I've been pinged!!!!!!
    {
		
        reply->icmp.type = 0; // Echo reply->icmp
		reply->icmp.code = 0; // Code for echo reply->icmp
		reply->icmp.id = packet->icmp.id; // Copy the ID from the request
		reply->icmp.seq = packet->icmp.seq; // Copy the sequence number from the request
		reply->icmp.checksum = 0; // Temporary value, will be calculated later
		memcpy(reply->payload, packet->payload, size); // Copy the payload from the original packet
		
		// Calculate checksum after setting all fields
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
		reply->icmp.checksum = ICMP_checksum_maker((u_short *) &reply->icmp, sizeof(ICMP) + size); // Calculate the checksum for the ICMP header		

		// Copy the ethernet header and IP headers
		reply->ehead = packet->ehead; // Copy the ethernet header
		memcpy(reply->ehead.dest, packet->ehead.src, sizeof(reply->ehead.dest)); // Swap source and destination MAC addresses
		memcpy(reply->ehead.src, packet->ehead.dest, sizeof(reply->ehead.src)); // Swap source and destination MAC addresses


		reply->ip = packet->ip; // Copy the IP header
		memcpy(reply->ip.dest, packet->ip.src, 4); // Swap source and destination IP addresses
		memcpy(reply->ip.src, packet->ip.dest, 4);
		reply->ip.len = byteswap16(sizeof(IPv4) + sizeof(ICMP) + size); // Set the length of the IP header
		reply->ip.frag_ident = byteswap16(0); // Set the fragment identifier to 0
		reply->ip.frag_offset = byteswap16(0); // Set the fragment offset to 0
		reply->ip.ttl = 64; // Set the TTL to 64
		reply->ip.csum = 0; // Temporary value, will be calculated later


#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
		reply->ip.csum = IPv4_checksum_maker((u_short *)&reply->ip, sizeof(IPv4)); // Calculate the checksum for the IP header

    }

	if(twig_debug)
	{
		printf("Attempting to write reply to pcap file\n");
		printf("ICMP Reply:\n");
		print_ICMP(&reply->icmp);
	}

	build_and_send_ICMP(reply, size);
}

u_short ICMP_checksum_maker(u_short *buffer, int size) {
	unsigned long sum = 0;

	// Sum up 16-bit words
	while (size > 1) {
		sum += *buffer++;
		size -= 2;
	}

	// Add any remaining byte
	if (size == 1) {
		sum += *(u_char *)buffer;
	}

	// Fold 32-bit sum to 16 bits
	while (sum >> 16) {
		sum =(sum & 0xFFFF) + (sum >> 16);
	}

	return ~sum;
}

u_short IPv4_checksum_maker(u_short *buffer, int size)
{
	unsigned long sum = 0;

	// Sum up 16-bit words
	while (size > 1) {
		sum += *buffer++;
		size -= 2;
	}

	// Add any remaining byte
	if (size == 1) {
		sum += *(u_char *)buffer;
	}

	// Fold 32-bit sum to 16 bits
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return ~sum;
}

void build_and_send_ICMP(ICMP_packet *packet, size_t size) {
	// Time to write to pcap file
	// pcap_pkthdr phead = packet->phead;
	ICMP icmp = packet->icmp;

	pcap_pkthdr pph;

	timeval temp_time;

	gettimeofday(&temp_time, NULL); // Get the current time
	pph.ts_secs = temp_time.tv_sec; // Copy the timestamp from the original packet
	pph.ts_usecs = temp_time.tv_usec; // Copy the microseconds from the original packet
	

	pph.caplen = sizeof(eth_hdr) + sizeof(IPv4) + icmp.length() + size; // Dynamically calculate the captured length, including the ICMP payload size
	pph.len = pph.caplen; // Set the actual length to the captured length

	if(twig_debug){
		printf("sizeof(pcap_pkthdr): %zu\n", sizeof(pcap_pkthdr));
		printf("sizeof(eth_hdr): %zu\n", sizeof(eth_hdr));
		printf("sizeof(IPv4): %zu\n", sizeof(IPv4));
		printf("sizeof(ICMP): %zu\n", sizeof(ICMP));
		printf("ICMP type : %d\n", icmp.type);
	}

	if(twig_debug || debug)
	{
		printf("### Sending ICMP Reply ###\n");
		print_ethernet(&packet->ehead); // Print the ethernet header for debugging
		print_IPv4(&packet->ip); // Print the IPv4 header for debugging
		print_ICMP(&packet->icmp); // Print the ICMP header for debugging
		printf("Payload: ");
		// Print the payload for debugging
		for (size_t i = 0; i < size; i++) {
			printf("%02x ", packet->payload[i]);
		}
		printf("\n Of size: %zu\n", size);
		printf("Total size of packet: %u, versus predicted: %zu\n", pph.caplen, sizeof(eth_hdr) + sizeof(IPv4) + sizeof(ICMP) + size);
	}

	// Build the packet here
	iovec out_packet[10];
	// pcap packet header, ethernet header, IP header, ICMP header, and payload
	out_packet[0].iov_base = &pph;
	out_packet[0].iov_len = sizeof(pph); 
	out_packet[1].iov_base = &packet->ehead;
	out_packet[1].iov_len = sizeof(eth_hdr); // Correctly calculate the size of the ethernet header
	out_packet[2].iov_base = &packet->ip;
	out_packet[2].iov_len = sizeof(IPv4); // Correctly calculate the size of the IPv4 header
	out_packet[3].iov_base = &packet->icmp;
	out_packet[3].iov_len = sizeof(ICMP); // Correctly calculate the size of the ICMP header
	out_packet[4].iov_base = packet->payload;
	out_packet[4].iov_len = size; // Correctly calculate the size of the payload

	// Send the out_packet here
	if(writev(fd, out_packet, 5) == -1) // Correct the number of iovec elements to include ICMP
	{
		perror("writev failed");
		free(packet);
		exit(1);
	}

}

void do_UDP(UDP_packet *packet, size_t size)
{
	if(twig_debug) printf("Doing UDP\n");

	
	// Build the UDP packet
	
	UDP_packet *reply;
	reply = (UDP_packet *)malloc(sizeof(ICMP_packet)); // Allocate memory for the ICMP packet
	if(reply == NULL) {
		perror("malloc failed for ICMP_packet reply");
		exit(1);
	}
	memcpy(reply->payload, packet->payload, size); // Copy the payload from the original packet so that way it's not a weird size
	memcpy(&reply->phead.ts_secs, &packet->phead.ts_secs, sizeof(packet->phead.ts_secs)); // Copy the timestamp from the original packet
	memcpy(&reply->phead.ts_usecs, &packet->phead.ts_usecs, sizeof(packet->phead.ts_usecs)); // Copy the timestamp from the original packet
	
	// Copy the ethernet header and IP headers
	reply->ehead = packet->ehead; // Copy the ethernet header
	memcpy(reply->ehead.dest, packet->ehead.src, sizeof(reply->ehead.dest)); // Swap source and destination MAC addresses
	memcpy(reply->ehead.src, packet->ehead.dest, sizeof(reply->ehead.src)); // Swap source and destination MAC addresses
	
	reply->ip = packet->ip; // Copy the IP header

	reply->ip.frag_offset = byteswap16(0); // Set the fragment offset to 0
	reply->ip.ttl = 64; // Set the TTL to 64
	reply->ip.csum = 0; // Temporary value, will be calculated later
	reply->ip.len = byteswap16(sizeof(IPv4) + sizeof(UDP) + size); // Set the length of the IP header
	reply->ip.frag_ident = byteswap16(0); // Set the fragment identifier to 0
	reply->ip.type = 0x11; // Set the protocol type to UDP
	memcpy(reply->ip.dest, packet->ip.src, 4); // Swap source and destination IP addresses
	memcpy(reply->ip.src, packet->ip.dest, 4);

	memcpy(&reply->udp, &packet->udp, sizeof(ICMP)); // Copy the ICMP header from the original packet

	if(byteswap16(packet->udp.dport) == 7) // We got an echo request (ping), we must reply!!! I've been pinged!!!!!!
    {
		reply->udp.sport = packet->udp.dport; // Copy the source port from the request
		reply->udp.dport = packet->udp.sport; // Copy the destination port from the request
		reply->udp.len = byteswap16(sizeof(UDP) + size); // Set the length of the UDP header
		reply->udp.checksum = 0; // Temporary value, will be calculated later
		memcpy(reply->payload, packet->payload, size); // Copy the payload from the original packet
	}
	else if(byteswap16(packet->udp.dport) == 37) // Time request
	{
		reply->udp.sport = packet->udp.dport; // Copy the source port from the request
		reply->udp.dport = packet->udp.sport; // Copy the destination port from the request
		reply->udp.checksum = 0; // Temporary value, will be calculated later
		
		// populate the payload with the current time

		u_int32_t now = std::chrono::duration_cast<std::chrono::seconds> (std::chrono::system_clock::now().time_since_epoch()).count();
		// Credit code to https://www.epochconverter.com/ ^
	
		memcpy(reply->payload, &now, sizeof(u_int32_t)); // Copy the time to the payload
		size = sizeof(u_int32_t); // Set the size to the size of the time payload

		reply->udp.len = byteswap16(sizeof(UDP) + size); // Set the length of the UDP header
		reply->ip.len = byteswap16(sizeof(IPv4) + sizeof(UDP) + size); // Set the length of the IP header
	}
	else
	{
		printf("Uhhh... idk..... hello world? (unknown UDP type)\n");
		free(reply);
		return;
	}

	
	// Calculate checksum after setting all fields 
	// THIS IS OPTIONAL SO I AM NOT DOING IT!
	// #pragma GCC diagnostic ignored "-Waddress-of-packed-member"
	// reply->udp.checksum = byteswap16(UDP_checksum_maker((u_short *) &reply->udp, sizeof(UDP) + size));



#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
	reply->ip.csum = IPv4_checksum_maker((u_short *)&reply->ip, sizeof(IPv4)); // Calculate the checksum for the IP header

	build_and_send_UDP(reply, size);
}

u_short UDP_checksum_maker(u_short *buffer, int size)
{
	unsigned long sum = 0;

	// Sum up 16-bit words
	while (size > 1) {
		sum += *buffer++;
		size -= 2;
	}

	// Add any remaining byte
	if (size == 1) {
		sum += *(u_char *)buffer;
	}

	// Fold 32-bit sum to 16 bits
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return ~sum;
}

void build_and_send_UDP(UDP_packet *packet, size_t size)
{
	// Time to write to pcap file
	// pcap_pkthdr phead = packet->phead;
	UDP udp = packet->udp;

	pcap_pkthdr pph;
	// pph.ts_secs = time(NULL); // Set the timestamp to the current time
	// pph.ts_usecs = 0; // Set the microseconds to 0

	timeval temp_time;

	gettimeofday(&temp_time, NULL); // Get the current time
	pph.ts_secs = temp_time.tv_sec; // Copy the timestamp from the original packet
	pph.ts_usecs = temp_time.tv_usec; // Copy the microseconds from the original packet
	
	pph.caplen = sizeof(eth_hdr) + sizeof(IPv4) + sizeof(udp) + size; // Dynamically calculate the captured length, including the ICMP payload size
	pph.len = pph.caplen; // Set the actual length to the captured length

	if(twig_debug){
		printf("sizeof(pcap_pkthdr): %zu\n", sizeof(pcap_pkthdr));
		printf("sizeof(eth_hdr): %zu\n", sizeof(eth_hdr));
		printf("sizeof(IPv4): %zu\n", sizeof(IPv4));
		printf("sizeof(UDP): %zu\n", sizeof(UDP));
	}

	if(twig_debug || debug)
	{
		printf("### Sending UDP Reply ###\n");
		print_ethernet(&packet->ehead); // Print the ethernet header for debugging
		print_IPv4(&packet->ip); // Print the IPv4 header for debugging
		print_UDP(&packet->udp); // Print the ICMP header for debugging
		printf("Payload: ");
		// Print the payload for debugging
		for (size_t i = 0; i < size; i++) {
			printf("%02x ", packet->payload[i]);
		}
		printf("\n Of size: %zu\n", size);
		printf("Total size of packet: %u, versus predicted: %zu\n", pph.caplen, sizeof(eth_hdr) + sizeof(IPv4) + sizeof(ICMP) + size);
	}

	// Build the packet here
	iovec out_packet[10];
	// pcap packet header, ethernet header, IP header, ICMP header, and payload
	out_packet[0].iov_base = &pph;
	out_packet[0].iov_len = sizeof(pph); 
	out_packet[1].iov_base = &packet->ehead;
	out_packet[1].iov_len = sizeof(eth_hdr); // Correctly calculate the size of the ethernet header
	out_packet[2].iov_base = &packet->ip;
	out_packet[2].iov_len = sizeof(IPv4); // Correctly calculate the size of the IPv4 header
	out_packet[3].iov_base = &packet->udp;
	out_packet[3].iov_len = sizeof(UDP); // Correctly calculate the size of the ICMP header
	out_packet[4].iov_base = packet->payload;
	out_packet[4].iov_len = size; // Correctly calculate the size of the payload

	// Send the out_packet here
	if(writev(fd, out_packet, 5) == -1) // Correct the number of iovec elements to include ICMP
	{
		perror("writev failed");
		free(packet);
		exit(1);
	}

}

