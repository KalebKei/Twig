#ifndef TWIG_UTILS_H
#define TWIG_UTILS_H

#include <stdlib.h>
#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <iomanip>
#include <vector>

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4

/* this normally comes from the pcap.h header file, but we'll just be using
* a few specific pieces, so we'll add them here
*
 * The first record in the file contains saved values for some
 * of the flags used in the printout phases of tcpdump.
 */

typedef int32_t bpf_int32;
typedef u_int32_t bpf_u_int32;

/* every pcap file starts with this structure */
struct pcap_file_header
{
    bpf_u_int32 magic;
    u_short version_major;
    u_short version_minor;
    bpf_int32 thiszone;   /* gmt to local correction; this is always 0 */
    bpf_u_int32 sigfigs;  /* accuracy of timestamps; this is always 0 */
    bpf_u_int32 snaplen;  /* max length saved portion of each pkt */
    bpf_u_int32 linktype; /* data link type (LINKTYPE_*) */
};

/*
 * Generic per-packet information, as supplied by libpcap.
 * this is the second record in the file, and every packet starts
 * with this structure (followed by the packet date bytes)
 */
struct pcap_pkthdr
{
    bpf_u_int32 ts_secs;  /* time stamp */
    bpf_u_int32 ts_usecs; /* time stamp */
    bpf_u_int32 caplen;   /* length of portion present */
    bpf_u_int32 len;      /* length of this packet (off wire) */
};


struct eth_hdr {
    /* create this structure */
	
	u_char dest[6];
	u_char src[6];  
	u_short type;
};

struct IPv4
{
    u_char hlen;
    u_char vers;
    u_short len;
    u_short frag_ident;
    u_short frag_offset;
    u_char ttl;
    u_char type;
    u_short csum;
    u_char src[4];
    u_char dest[4];
};

struct ARP
{
    u_short htype;
    u_short ptype;
    u_char hlen;
    u_char plen;
    u_short op;
    u_char sha[6];
    u_char spa[4];
    u_char tha[6];
    u_char tpa[4];
};

struct UDP {
    u_short sport;
    u_short dport;
    u_short len;
    u_short checksum;
};

struct TCP {
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char off;
    u_char flags;
    u_short win;
    u_short csum;
    u_short urg;
};

struct ICMP {
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short seq;

    size_t length() const {
        return sizeof(u_char)*2 + sizeof(u_short)*3;
    }
};

struct __attribute__((__packed__)) ICMP_packet { // thank you Silas
    pcap_pkthdr phead;
    eth_hdr ehead;
    IPv4 ip;
    ICMP icmp;
    char payload[65535]; // Flexible array member for ICMP payload
};

struct __attribute__((__packed__)) UDP_packet { // thank you Silas
    pcap_pkthdr phead;
    eth_hdr ehead;
    IPv4 ip;
    UDP udp;
    char payload[65535]; // Flexible array member for UDP payload
};

#endif