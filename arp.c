#include <net/if_arp.h>
#include <netinet/ether.h>

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

int arp_write_mac(char *dst, char *src) {
	int seg = 0;
	char ind;
	int i, j = 0;
	
	for (i = 0; i < 17; i++) {
		ind = src[i];
		if (ind >= '0' && ind <= '9')
			seg += ind + '0';
		else if (ind == ':') {
			dst[j++] = (unsigned char) seg;
			seg = 0;
		}
		else
			return -1;
	}
	return 0;
}

int arp_write_ip(char *dst, char *src) {
	int seg = 0;
	char ind;
	int i, j = 0;
	
	for (i = 0; i < 15; i++) {
		ind = src[i];
		if (ind >= '0' && ind <= '9')
			seg += ind + '0';
		else if (ind == '.') {
			dst[j++] = (unsigned char) seg;
			seg = 0;
		}
		else if (ind == '\0')
			break;
		else
			return -1;
	}
	return 0;
}

char* arp_hdr_writer(struct packet_data sp_pd, char *cp_cur) {
	struct arp_packet *pkt = (struct arp_packet *)cp_cur;
	
	pkt->hw_type = htons(sp_pd.arp_hw_type);
	pkt->proto_type = htons(sp_pd.arp_proto_type);
	pkt->hw_len = (unsigned char) htons(sp_pd.arp_hw_len);
	pkt->proto_len = (unsigned char) htons(sp_pd.arp_proto_len);
	pkt->op = htons(sp_pd.ar_op);

	if (arp_write_mac(pkt->src_mac, sp_pd.arp_src_mac)) {
		fprintf(stderr, "ARP: src_mac convertion error\n");
		goto err;
	}

	if (arp_write_mac(pkt->dst_mac, sp_pd.arp_dst_mac)) {
		fprintf(stderr, "ARP: dst_mac convertion error\n");
		goto err;
	}

	if (arp_write_ip(pkt->src_ip, sp_pd.arp_src_ip)) {
		fprintf(stderr, "ARP: src_ip convertion error\n");
		goto err;
	}

	if (arp_write_ip(pkt->dst_ip, sp_pd.arp_dst_ip)) {
		fprintf(stderr, "ARP: dst_ip convertion error\n");
		goto err;
	}

	return (cp_cur + sizeof(struct arp_packet));
err:
	return NULL;
}
