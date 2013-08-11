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

struct ndisc_na_pkt {
	uint32_t RSO_res;
	uint8_t target_addr[16];
	/**
	 * data is just a place holder. It only specifies the starting address.
	 * The entire value from NDISC_NS_OPTION option will be dumped here.
	 * So user should take care of the buffer size.
	 */
	uint8_t option;
};

struct ndisc_rs_pkt {
	/* Reserved Field. Initialized to zero */
	uint32_t res;
	/**
	 * data is just a place holder. It only specifies the starting address.
	 * The entire value from NDISC_NS_OPTION option will be dumped here.
	 * So user should take care of the buffer size.
	 */
	uint8_t option;
};

struct ndisc_ra_pkt {
	uint8_t cur_hop_limit;
	/* m(1) + o(1) + res(6) */
	uint8_t m_o_res;
	uint16_t router_lifetime;
	uint32_t reachable_time;
	uint32_t retrans_timer;
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

char* pgen_ndisc_ra_writer(FILE *fp, char *cp_cur) {
	struct ndisc_ra_pkt *pkt = (struct ndisc_ra_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];

	/**
	 * Having 7 items
	 * 1. Cur_Hop_Limit - 1B
	 * 2. M flag - 1b
	 * 3. O flag - 1b
	 * 4. Router Lifetime - 2B
	 * 5. Reachable Time - 4B
	 * 6. Retrans Time - 4B
	 * 7. Option - variable length
	 *----------------------------
	 * 8. Total number of options
	 */
	int items = 8, tmp, op_len = 0, op_num;
	char *op;

	while (items--) {
		printf("outer while loop\n");
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "NDISC_RA_CUR_HOP_LIMIT")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->cur_hop_limit = (uint8_t)tmp;
		}
		else if (!strcmp(option, "NDISC_RA_M_FLAG")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			if (tmp)
				pkt->m_o_res |= 0x80;
		}
		else if (!strcmp(option, "NDISC_RA_O_FLAG")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			if (tmp)
				pkt->m_o_res |= 0x40;
		}
		else if (!strcmp(option, "NDISC_RA_ROUTER_LIFETIME")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->router_lifetime = htons(tmp);
		}
		else if (!strcmp(option, "NDISC_RA_REACHABLE_TIME")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->reachable_time = htonl(tmp);
		}
		else if (!strcmp(option, "NDISC_RA_RETRANS_TIMER")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->retrans_timer = htonl(tmp);
		}
		else if (!strcmp(option, "NDISC_RA_OPTION_NUM")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			op_num = tmp;
		}
		else if (!strcmp(option, "NDISC_RA_OPTION")) {
			op = (char *)&(pkt->option);

			/**
			 * Only three known options as of now [RFC-4681] 
			 * 1. Source Link Address
			 * 2. Prefix Information
			 * 3. MTU
			 */

			while (op_num--) {
				printf("\n\n In while loop, %s %d\n\n", value, op_num);
				if (!strcmp(value, "NO_OPTION"))
					op_len = 0;

				else if (!strcmp(value, "NDISC_RA_SRC_LINK_ADDR")) {
					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_OP_TYPE")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						*op = (uint8_t)tmp;
						op++;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_OP_LEN")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						*op = (uint8_t)tmp;
						op++;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_OP_LEN_ORIG")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						op_len += tmp * 8;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_OP_SRC_LINK_ADDR")) {
						if (mac_writer(op, value))
							goto err;
						op += 6;
					}
					else
						goto err;
				}
				else if (!strcmp(value, "NDISC_RA_PREFIX_INFO")) {
					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_OP_TYPE")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						*op = (uint8_t)tmp;
						op++;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_OP_LEN")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						*op = (uint8_t)tmp;
						op++;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_OP_LEN_ORIG")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						op_len += tmp * 8;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_PREFIX_LEN")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						*op = (uint8_t)tmp;
						op++;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_L_FLAG")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						if (tmp)
							*op |= 0x80;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_A_FLAG")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						if (tmp)
							*op |= 0x40;
					}
					else
						goto err;

					op++;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_PREFIX_VALID_LIFETIME")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						tmp = htonl(tmp);
						memcpy(op, &tmp, 4);
						op += 4;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_PREFIX_PREFERRED_LIFETIME")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						tmp = htonl(tmp);
						memcpy(op, &tmp, 4);
						op += 4;
					}
					else
						goto err;

					/* 4 Bytes Reserved */
					op += 4;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_PREFIX")) {
						if (ip6_prefix_writer(op, value))
							goto err;
						op += 16;
					}
					else
						goto err;
				}
				else if (!strcmp(value, "NDISC_RA_MTU")) {
					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_TYPE")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						*op = (uint8_t)tmp;
						op++;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_LEN")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						*op = (uint8_t)tmp;
						op++;
					}
					else
						goto err;

					/* 2 Bytes Reserverd */
					op += 2;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_LEN_ORIG")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						op_len += tmp * 8;
					}
					else
						goto err;

					if (pgen_parse_option(fp, option, value))
						goto err;
					if (!strcmp(option, "NDISC_RA_MTU")) {
						if (pgen_store_dec(&tmp, value))
							goto err;
						tmp = htonl(tmp);
						memcpy(op, &tmp, 4);
						op += 4;
					}
					else
						goto err;
				}
				else {
					printf("4");
					goto err;
				}

				if (op_num && pgen_parse_option(fp, option, value)) {
					printf("3");
					goto err;
				}
				if (op_num && strcmp(option, "NDISC_RA_OPTION")) {
					printf("2");
					goto err;
				}
			}
		}
		else {
			printf("1");
			goto err;
		}
	}

	printf("\n\nExiting\n");
	printf("\n\n %d \n\n", op_len);
	return (cp_cur + 16 + op_len);

err:
	printf("\n\n Error\n");
	return NULL;
}

char* pgen_ndisc_rs_writer(FILE *fp, char *cp_cur) {
	struct ndisc_rs_pkt *pkt = (struct ndisc_rs_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];

	/**
	 * Having 1 item
	 * 1. Option - variable length
	 */
	int  tmp, op_len;

	if (pgen_parse_option(fp, option, value))
		goto err;

	if (!strcmp(option, "NDISC_RS_OPTION")) {
		if (!strcmp(value, "NO_OPTION"))
			op_len = 0;
		else if (!strcmp(value, "NDISC_RS_SRC_LINK_ADDR")) {
			char *op = (char *)&(pkt->option);

			if (pgen_parse_option(fp, option, value))
				goto err;
			if (!strcmp(option, "NDISC_RS_OP_TYPE")) {
				if (pgen_store_dec(&tmp, value))
					goto err;
				*op = (uint8_t)tmp;
				op++;
			}
			else
				goto err;

			if (pgen_parse_option(fp, option, value))
				goto err;
			if (!strcmp(option, "NDISC_RS_OP_LEN")) {
				if (pgen_store_dec(&tmp, value))
					goto err;
				*op = (uint8_t)tmp;
				op++;
			}
			else
				goto err;

			if (pgen_parse_option(fp, option, value))
				goto err;
			if (!strcmp(option, "NDISC_RS_OP_LEN_ORIG")) {
				if (pgen_store_dec(&tmp, value))
					goto err;
				op_len = tmp * 8;
			}
			else
				goto err;

			if (pgen_parse_option(fp, option, value))
				goto err;
			if (!strcmp(option, "NDISC_RS_OP_SRC_LINK_ADDR")) {
				if (mac_writer(op, value))
					goto err;
				op += 6;
			}
			else
				goto err;
		}
		else
			goto err;
	}
	else
		goto err;

	/* len = res(4) + op_len */
	return (cp_cur + 4 + op_len);

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
				else
					goto err;

				/* len is in 8 octets uint */
				op_len = tmp * 8;
			}
			else
				goto err;
		}
		else
			goto err;
	}

	/* len = Reserved(4) + Target_addr(16) + op_len */
	return (cp_cur + 4 + 16 + op_len);
err:
	return NULL;
}

char* pgen_ndisc_na_writer(FILE *fp, char *cp_cur) {
	struct ndisc_na_pkt *pkt = (struct ndisc_na_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/* Totally 4 options: R, S, O flag & target addr */
	int items = 5, tmp, op_len;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "NDISC_NA_R")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			if (tmp)
				pkt->RSO_res |= 0x80000000;
		}
		else if (!strcmp(option, "NDISC_NA_S")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			if (tmp)
				pkt->RSO_res |= 0x40000000;
		}
		else if (!strcmp(option, "NDISC_NA_O")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			if (tmp)
				pkt->RSO_res |= 0x20000000;
		}
		else if (!strcmp(option, "NDISC_NA_TARGET_ADDR")) {
			if (ip6_writer(pkt->target_addr, value))
				goto err;
		}
		else if (!strcmp(option, "NDISC_NA_OPTION")) {
			if (!strcmp(value, "NO_OPTION"))
				op_len = 0;

			/* This is only known option as of now. [RFC-4861] */
			else if (!strcmp(value, "NDISC_NA_SRC_LINK_ADDR")) {
				char *op_ptr = (char *)&(pkt->option);

				if (pgen_parse_option(fp, option, value))
					goto err;
				if (!strcmp(option, "NDISC_NA_OP_TYPE")) {
					if (pgen_store_dec(&tmp, value))
						goto err;
					*op_ptr = (uint8_t)tmp;
					op_ptr++;
				}
				else
					goto err;

				if (pgen_parse_option(fp, option, value))
					goto err;
				if (!strcmp(option, "NDISC_NA_OP_LEN")) {
					if (pgen_store_dec(&tmp, value))
						goto err;
					*op_ptr = (uint8_t)tmp;
					op_ptr++;
				}
				else
					goto err;

				if (pgen_parse_option(fp, option, value))
					goto err;
				if (!strcmp(option, "NDISC_NA_OP_TAR_LINK_ADDR")) {
					if (mac_writer(op_ptr, value))
						goto err;
				}
				else
					goto err;

				op_len = tmp * 8;
			}
			else
				goto err;
		}
		else
			goto err;
	}

	pkt->RSO_res = htonl(pkt->RSO_res);

	/* len = RSO_resvered(4) + Target_addr(16) + op_len */
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
	else if (!strcmp(option, "NDISC_NA"))
		cp_cur = pgen_ndisc_na_writer(fp, cp_cur);
	else if (!strcmp(option, "NDISC_RS"))
		cp_cur = pgen_ndisc_rs_writer(fp, cp_cur);
	else if (!strcmp(option, "NDISC_RA"))
		cp_cur = pgen_ndisc_ra_writer(fp, cp_cur);
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
