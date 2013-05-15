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

	return (cp_cur + sizeof(struct ipv6_packet));

err:
	return NULL;
}
