#include <net/if_arp.h>

#include "pgen.h"

struct arp_packet {
	unsigned short hw_type;
	unsigned short proto_type;
	unsigned char hw_len;
	unsigned char proto_len;
	unsigned short op;
	unsigned char src_mac[6];
	unsigned char src_ip[4];
	unsigned char dst_mac[6];
	unsigned char dst_ip[4];
};

char* pgen_arp_hdr_writer(struct packet_data *sp_pd, char *cp_cur) {
	struct arp_packet *pkt = (struct arp_packet *)cp_cur;

	pkt->hw_type =  htons(sp_pd->arp_hw_type);
	pkt->proto_type = htons(sp_pd->arp_proto_type);
	pkt->hw_len = (unsigned char) sp_pd->arp_hw_len;
	pkt->proto_len = (unsigned char) sp_pd->arp_proto_len;
	pkt->op = htons(sp_pd->arp_opcode);

	if (mac_writer(pkt->src_mac, sp_pd->arp_src_mac)) {
		fprintf(stderr, "ARP: src_mac convertion error\n");
		goto err;
	}

	if (mac_writer(pkt->dst_mac, sp_pd->arp_dst_mac)) {
		fprintf(stderr, "ARP: dst_mac convertion error\n");
		goto err;
	}

	if (ip4_writer(pkt->src_ip, sp_pd->arp_src_ip)) {
		fprintf(stderr, "ARP: src_ip convertion error\n");
		goto err;
	}

	if (ip4_writer(pkt->dst_ip, sp_pd->arp_dst_ip)) {
		fprintf(stderr, "ARP: dst_ip convertion error\n");
		goto err;
	}

	return (cp_cur + sizeof(struct arp_packet));
err:
	return NULL;
}
