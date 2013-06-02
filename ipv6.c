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

struct hbh_packet {
	uint8_t nxt_hdr;
	uint8_t ext_len;
	char data;
};

struct routing_hdr_packet {
	uint8_t nxt_hdr;
	uint8_t ext_len;
	uint8_t type;
	uint8_t seg_left;
	uint8_t data;
};

int hbh_option_writer(char *buff, char *value) {
	uint8_t byte = 0;
	uint32_t len = 0;

	if ((buff == NULL) || (value == NULL))
		goto err;

	if (*value++ != '0' && (*value != 'x' || *value != 'X'))
		goto err;

	while (*(++value) != '\0') {
		len++;
		if (*value >= '0' && *value <= '9')
			byte = byte * 16 + *value - '0';
		else if (*value >= 'a' && *value <= 'f')
			byte = byte * 16 + *value - 'a' + 10;
		else if (*value >= 'A' && *value <= 'F')
			byte = byte * 16 + *value - 'A' + 10;
		else
			goto err;

		if (len % 2 == 0) {
			*buff++ = byte;
			byte = 0;
		}
	}

	if (len % 2 != 0)
		goto err;
	else
		return len/2;

err:
	return -1;
}

char* ipv6_routing_hdr_writer(FILE *fp, char *cp_cur) {
	struct routing_hdr_packet *pkt = (struct routing_hdr_packet *)cp_cur;
	uint8_t option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	int32_t items = 5, tmp, len = 0, type, oitems;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "RH_NXT_HDR")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->nxt_hdr = (uint8_t)tmp;
		}
		else if (!strcmp(option, "RH_EXT_LEN")) {
			if (pgen_store_dec(&len, value))
				goto err;
			pkt->ext_len = (uint8_t)len;
		}
		else if (!strcmp(option, "RH_TYPE")) {
			if (pgen_store_dec(&type, value))
				goto err;
			pkt->type = (uint8_t)type;
		}
		else if (!strcmp(option, "RH_SEG_LEFT")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->seg_left = (uint8_t)tmp;
		}
		else if (!strcmp(option, "RH_DATA")) {
			/* Type 0 Routing Header */
			if (type == 0) {
				oitems = len / 2;
				while (oitems) {
					if (pgen_parse_option(fp, option, value))
						goto err;
					if (strcmp(option, "RH_ADDR"))
						goto err;
					if (ip6_writer(((&pkt->data)+(((len/2)-oitems)*16)+4), value))
						goto err;
					oitems--;
				}
			}
		}
	}
	return cp_cur + 8*(len+1);
err:
	PGEN_INFO("Errno at writing Routing Header");
	PGEN_PRINT_DATA("Option: %s\tValue: %s\n", option, value);
	return NULL;
}

char* ipv6_hbh_writer(FILE *fp, char *cp_cur) {
	struct hbh_packet *pkt = (struct hbh_packet *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	int items = 3, tmp, len = 0;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "HBH_NXT_HDR")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->nxt_hdr = (uint8_t)tmp;
		}
		else if (!strcmp(option, "HBH_HDR_EXT_LEN")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->ext_len = (uint8_t)tmp;
		}
		else if (!strcmp(option, "HBH_OPTION")) {
			len = hbh_option_writer(&pkt->data, value);
			if (len < 0)
				goto err;
		}
		else
			goto err;
	}
	return (cp_cur + len + 2);

err:
	return NULL;
}

char* pgen_ipv6_writer(FILE *fp, char *cp_cur) {
	struct ipv6_packet *pkt = (struct ipv6_packet *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/* 
	 * Totally we have 9 items in IPv6 header.
	 * 8 items for packet.
	 * 1 is the number of extention headers
	 */
	int hdr_items = 9, tmp, ext_hdrs;

	pkt->ver_tc_fw = 0;

	while (hdr_items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "IPV6_VERSION")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->ver_tc_fw |= tmp << 28;
		}
		else if (!strcmp(option, "IPV6_TRAFFIC_CLASS")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->ver_tc_fw |= tmp << 20;
		}
		else if (!strcmp(option, "IPV6_FLOW_LABEL")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->ver_tc_fw |= tmp;
		}
		else if (!strcmp(option, "IPV6_PAYLOAD_LENGTH")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->payload_length = htons(tmp);
		}
		else if (!strcmp(option, "IPV6_NEXT_HEADER")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->next_header = (uint8_t)tmp;
		}
		else if (!strcmp(option, "IPV6_HOP_LIMIT")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->hop_limit = (uint8_t)tmp;
		}
		else if (!strcmp(option, "IPV6_SRC_ADDR")) {
			if (ip6_writer(pkt->src, value))
				goto err;
		}
		else if (!strcmp(option, "IPV6_DST_ADDR")) {
			if (ip6_writer(pkt->dst, value))
				goto err;
		}
		else if (!strcmp(option, "IPV6_EXT_HDRS")) {
			if (pgen_store_dec(&ext_hdrs, value))
				goto err;
		}
		else
			goto err;
	}
	pkt->ver_tc_fw = htonl(pkt->ver_tc_fw);
	cp_cur = cp_cur + sizeof(struct ipv6_packet);

	/* Writing IPv6 extention headers */
	while (ext_hdrs--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "HOP_BY_HOP")) {
			cp_cur = ipv6_hbh_writer(fp, cp_cur);
		}
		else if (!strcmp(option, "ROUTING_HEADER")) {
			cp_cur = ipv6_routing_hdr_writer(fp, cp_cur);
		}
		else
			goto err;

		if (cp_cur == NULL)
			goto err;
	}
#if 0
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
#endif

	return cp_cur;

err:
	PGEN_INFO("Unknown IPv6 Option");
	PGEN_PRINT_DATA("Option: %s\tValue: %s\n", option, value);
	return NULL;
}
