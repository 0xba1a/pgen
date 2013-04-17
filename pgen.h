#ifndef PGEN_H
#define PGEN_H 1

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <errno.h>
#include <linux/limits.h>

#define DEF_PGEN_CONF "/etc/pgen.conf"
#define ETH_ALEN 6

struct packet_data {
	/* common data */
	char conf_file[PATH_MAX];
	size_t buff_size;

	/* sending socket address info */
	char if_name[IFNAMSIZ];
	char pk_dst_mac[18];

	/* ethernet header data */
	int ether_hdr;
	char src_mac[18];
	char dst_mac[18];
	int ether_type;

	/* ARP packet data */
	int arp;
	int arp_hw_type;
	int arp_proto_type;
	int arp_hw_len;
	int arp_proto_len;
	int arp_opcode;
	char arp_src_mac[18];
	char arp_dst_mac[18];
	char arp_src_ip[16];
	char arp_dst_ip[16];
};

int set_option(struct packet_data *, const char *, const char *);
char* ethr_hdr_writer(struct packet_data *, char *);
char* arp_hdr_writer(struct packet_data *, char *);

/* Helpers */
void usage();
int pgen_strcmp(const char *, const char *);
int send_packet(struct packet_data *, const char *);
int mac_writer(char *, const char *);
int ip4_writer(char *, const char *);
#endif /* PGEN_H */
