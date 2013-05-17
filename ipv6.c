#include "pgen.h"

struct ipv6_packet {
	/* 
	 version 4 bits
	 traffic-class 8 bits
	 flow-label 20 bits
	 */
	uint32_t ver_tc_fw;
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t hop_limit;
	uint8_t src[16];
	uint8_t dst[16];
};

struct ipv6_hop_by_hop {
	uint8_t nxt_hdr;
	uint8_t ext_len;
	void *data;
};

char* pgen_ipv6_ext_writer(struct packet_data *sp_pd, char *cp_cur) {
	int i;
	struct ipv6_extention *ipv6_ext = sp_pd->ipv6_ext;

	for (i = 0; i < sp_pd->ipv6_ext_hdr; i++) {
		
		/* Hop-By-Hop extention header */
		if (ipv6_ext->hdr_type == 0) {
			struct ipv6_hop_by_hop *hbh = (struct ipv6_hop_by_hop *)cp_cur;
			hbh->nxt_hdr = 1; /// add conf option for this option
			hbh->ext_len = 4; /// consider the approach. something is wrong
			memcpy(hbh->data, ipv6_ext->data, 4);
			ipv6_ext = ipv6_ext->next;
			cp_cur = cp_cur + hbh->ext_len + 1;
		}
	}

	return cp_cur;
}

char* pgen_ipv6_hdr_writer(struct packet_data *sp_pd, char *cp_cur) {
	struct ipv6_packet *pkt = (struct ipv6_packet *)cp_cur;

	pkt->ver_tc_fw = 0;
	pkt->ver_tc_fw |= sp_pd->ipv6_version << 28;
	pkt->ver_tc_fw |= sp_pd->ipv6_traffic_class << 20;
	pkt->ver_tc_fw |= sp_pd->ipv6_flow_label;

	pkt->ver_tc_fw = htonl(pkt->ver_tc_fw);
	pkt->payload_length = htons(sp_pd->ipv6_payload_length);
	pkt->next_header = (uint8_t)sp_pd->ipv6_next_header;
	pkt->hop_limit = (uint8_t)sp_pd->ipv6_hop_limit;

	if (ip6_writer(pkt->src, sp_pd->ipv6_src)) {
		fprintf(stderr, "IPV6: src_ip conversion failed\n");
		goto err;
	}

	if (ip6_writer(pkt->dst, sp_pd->ipv6_dst)) {
		fprintf(stderr, "IPV6: dst_ip conversion failed\n");
		goto err;
	}

	cp_cur = pgen_ipv6_ext_writer(sp_pd, cp_cur + sizeof(struct ipv6_packet));

	return cp_cur;

err:
	return NULL;
}
