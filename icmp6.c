#include "pgen.h"

struct icmp6_hdr{
	uint8_t type;
	uint8_t code;
	int16_t checksum;
};

struct echo6_pkt {
	uint16_t identifier;
	uint16_t seq_num;
	/**
	 * data is just a place holder. It only specifies the starting address.
	 * The entire value from ECHO6_DATA option will be dumped here.
	 * So user should take care of the buffer size.
	 */
	uint8_t data;
};

struct ndisc_ns_pkt {
	uint32_t reserved;
	uint8_t target_addr[16];
	/**
	 * data is just a place holder. It only specifies the starting address.
	 * The entire value from NDISC_NS_OPTION option will be dumped here.
	 * So user should take care of the buffer size.
	 */
	uint8_t option;
};

int calculate_icmp6_checksum(struct icmp6_hdr *pkt, int len, FILE *fp) {
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	uint32_t checksum = 0;
	int init_pos, pos;
	char src[16] = {0}, dst[16] = {0};
	uint16_t tmp = 0;
	uint16_t *icmp6_pkt = (uint16_t *)pkt;
	int i;
	int len1;

	/* store the current position of cursur in the conf file */
	init_pos = ftell(fp);
	if (init_pos < 0)
		goto err;

	/* Move cursur to the starting of conf file */
	if (fseek(fp, 0, SEEK_SET))
		goto err;

	/* Find immediate src and dst addresses from current pos */
	do {
		if (pgen_parse_option(fp, option, value))
			goto err;

		pos = ftell(fp);

		if (!strcmp(option, "IPV6_SRC_ADDR")) {
			if (ip6_writer(src, value))
				goto err;
		}
		else if (!strcmp(option, "IPV6_DST_ADDR")) {
			if (ip6_writer(dst, value))
				goto err;
		}
	} while ((pos != -1) && (pos < init_pos));

	if (pos == -1)
		goto err;

	/* Process ipv6 src and dst addresses for checksum */
	for (i = 0; i < 16; i += 2) {
		checksum += (((src[i] & 0xff) << 8) | (src[i+1] & 0xff));
		checksum += (((dst[i] & 0xff) << 8) | (dst[i+1] & 0xff));
	}

	/* process length of the icmpv6 message */	
	checksum += len;

	/* Process packet type. Packet type is always icmpv6 */
	checksum += 0x3a;

	/* Process icmpv6 packet data */
	while (len > 1) {
		checksum += htons(*icmp6_pkt);
		icmp6_pkt++;
		len -= 2;
	}
	if (len > 0)
		checksum += ((*(uint8_t *)icmp6_pkt) << 8);

	/* Make it into 16 bits */
	while (checksum >> 16 != 0)
		checksum = (checksum & 0xffff) + (checksum >> 16);

	/* One's complement */
	checksum = ~checksum;

	/**
	 * The checksum is the 16-bit one's complement of the one's complement
	 * sum of the entire ICMPv6 message starting with the ICMPv6 message
	 * type field, prepended with a "pseudo-header" of IPv6 header fields
	 * having only src addr, dst addr and packet type.
	 * [Ref: RFC2463]
	 */
	pkt->checksum = htons((uint16_t)checksum);

	if (fseek(fp, init_pos, SEEK_SET))
		goto err;

	return 0;

err:
	return -1;
}

char* pgen_echo6_writer(FILE *fp, char *cp_cur) {
	struct echo6_pkt *pkt = (struct echo6_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	int items = 3, tmp, len;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "ECHO6_IDENTIFIER")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->identifier = htons(tmp);
		}
		else if (!strcmp(option, "ECHO6_SEQ")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->seq_num = htons(tmp);
		}
		else if (!strcmp(option, "ECHO6_DATA")) {
			if (!strcmp(value, "NO_DATA"))
				len = 0;
			else {
				len = option_writer(&(pkt->data), value);
				if (len == 0)
					goto err;
			}
		}
	}
	return cp_cur + len + 4;
err:
	return NULL;
}

char* pgen_ndisc_ns_writer(FILE *fp, char *cp_cur) {
	struct ndisc_ns_pkt *pkt = (struct ndisc_ns_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/* Having only two items. 1.Target address 2.Option */
	int items = 2, tmp, op_len;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "NDISC_NS_TARGET_ADDR")) {
			if (ip6_writer(pkt->target_addr, value))
				goto err;
		}
		else if (!strcmp(option, "NDISC_NS_OPTION")) {
			if (!strcmp(value, "NO_OPTION"))
				op_len = 0;
			/* This is only known option as of now. [RFC-4861] */
			else if (!strcmp(value, "NDISC_NS_SRC_LINK_ADDR")) {
				char *op_ptr = (char *)&(pkt->option);

				if (pgen_parse_option(fp, option, value))
					goto err;
				if (!strcmp(option, "NDISC_NS_OP_TYPE")) {
					if (pgen_store_dec(&tmp, value))
						goto err;
					*op_ptr = (uint8_t)tmp;
					op_ptr++;
				}
				else
					goto err;

				if (pgen_parse_option(fp, option, value))
					goto err;
				if (!strcmp(option, "NDISC_NS_OP_LEN")) {
					if (pgen_store_dec(&tmp, value))
						goto err;
					*op_ptr = (uint8_t)tmp;
					op_ptr++;
				}
				else
					goto err;

				if (pgen_parse_option(fp, option, value))
					goto err;
				if (!strcmp(option, "NDISC_NS_OP_SRC_LINK_ADDR")) {
					if (mac_writer(op_ptr, value))
						goto err;
				}

				/* len is in 8 octets uint */
				op_len = tmp * 8;
			}
		}
		else
			goto err;
	}

	/* len = Reserved(4) + Target_addr(16) + op_len */
	return (cp_cur + 4 + 16 + op_len);
err:
	return NULL;
}

char* pgen_icmp6_writer(FILE *fp, char *cp_cur) {
	struct icmp6_hdr *pkt = (struct icmp6_hdr *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	int hdr_items = 3, tmp;
	int calculate_cksum = 0;

	while (hdr_items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "ICMP6_TYPE")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->type = (uint8_t)tmp;
		}
		else if (!strcmp(option, "ICMP6_CODE")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->code = (uint8_t)tmp;
		}
		else if (!strcmp(option, "ICMP6_CHECKSUM")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			if (tmp == -1)
				calculate_cksum = 1;
			else
				pkt->checksum = (uint16_t)tmp;
		}
	}
	cp_cur += sizeof(struct icmp6_hdr);

	if (pgen_parse_option(fp,option, value))
		goto err;

	if (!strcmp(option, "NO_ICMP6_BODY"));
		/* we are fine here. Do nothing */
	else if (!strcmp(option, "ECHO_REQ"))
		cp_cur = pgen_echo6_writer(fp, cp_cur);
	else if (!strcmp(option, "ECHO_REP"))
		cp_cur = pgen_echo6_writer(fp, cp_cur);
	else if (!strcmp(option, "NDISC_NS"))
		cp_cur = pgen_ndisc_ns_writer(fp, cp_cur);
	else
		goto err;

	if (cp_cur == NULL)
		goto err;

	if (calculate_cksum) {
		if (calculate_icmp6_checksum(pkt, (cp_cur - (char *)pkt), fp)) {
			PGEN_INFO("error at calculating icmp6 checksum\n");
			goto err;
		}
	}

	return cp_cur;

err:
	return NULL;
}
