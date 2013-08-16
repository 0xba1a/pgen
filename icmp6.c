/**
 * This file is part of pgen, a packet generator tool.
 * Copyright (C) 2013  Balakumaran Kannan <kumaran.4353@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
	/* 4-Byte reserved data */
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
	/* R, S, O flag [1-bit each] and 29-bits resvered */
	uint32_t RSO_res;
	uint8_t target_addr[16];
	/**
	 * data is just a place holder. It only specifies the starting address.
	 * The entire value from NDISC_NA_OPTION option will be dumped here.
	 * So user should take care of the buffer size.
	 */
	uint8_t option;
};

struct ndisc_rs_pkt {
	/* 4-Byte reserved field */
	uint32_t res;
	/**
	 * data is just a place holder. It only specifies the starting address.
	 * The entire value from NDISC_RS_OPTION option will be dumped here.
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
	 * The entire value from NDISC_RA_OPTION option will be dumped here.
	 * So user should take care of the buffer size.
	 */
	uint8_t option;
};

/**
 * @param	pkt		The packet buffer
 * @param	len		length of the ICMPv6 packet
 * @param	fp		file pointer to the configuration file
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		This function reads the ICMPv6 packet, calculates checksum and fills
 * the checksum field in the packet.
 * [RFC-4443]
 * The checksum is the 16-bit one's complement of the one's complement sum of
 * the entire ICMPv6 message, starting with the ICMPv6 message type field, and
 * prepended with a "pseudo-header" of IPv6 header fields...
 */
int32_t calculate_icmp6_checksum(struct icmp6_hdr *pkt, int32_t len, FILE *fp) {
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	uint32_t checksum = 0;
	int32_t init_pos, pos;
	char src[16] = {0}, dst[16] = {0};
	uint16_t tmp = 0;
	uint16_t *icmp6_pkt = (uint16_t *)pkt;
	int32_t i;

	/* store the current position of cursur in the conf file */
	init_pos = ftell(fp);
	if (init_pos < 0)
		goto err;

	/* Move cursur to the starting of conf file */
	if (fseek(fp, 0, SEEK_SET))
		goto err;

	/* Find src and dst addresses that immediately above from current pos */
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
	 * [Ref: RFC-2463 same in RFC-4443]
	 */
	pkt->checksum = htons((uint16_t)checksum);

	/* Restore the file position for furthur processing */
	if (fseek(fp, init_pos, SEEK_SET))
		goto err;

	return 0;

err:
	PGEN_INFO("Error while writing ICMPv6 checksum");
	return -1;
}

/**
 * @param	fp		file pointer to the configuration file
 * @param	cp_cur	the packet buffer
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes ICMPv6 echo6 packet
 */
char* pgen_echo6_writer(FILE *fp, char *cp_cur) {
	struct echo6_pkt *pkt = (struct echo6_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * Three itmes need for an echo6 packet
	 *
	 * 1. Identifier
	 * 2. Sequence number
	 * 3. Data
	 */
	int32_t items = 3, tmp, len;

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
	PGEN_INFO("Error while writing echo6 packet"); 
	return NULL;
}

/**
 * @param	fp		file pointer to the configuration file
 * @param	cp_cur	the packet buffer
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes ICMPv6 Router Advertisement packet
 */
char* pgen_ndisc_ra_writer(FILE *fp, char *cp_cur) {
	struct ndisc_ra_pkt *pkt = (struct ndisc_ra_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];

	/**
	 * Totally 7 items for packet
	 * 1. Cur_Hop_Limit - 1B
	 * 2. M flag - 1b
	 * 3. O flag - 1b
	 * 4. Router Lifetime - 2B
	 * 5. Reachable Time - 4B
	 * 6. Retrans Time - 4B
	 * 7. Option - variable length
	 *----------------------------
	 *
	 * And one for program control
	 * 8. Total number of options
	 */
	int32_t items = 8, tmp, op_len = 0, op_num;
	char *op;

	while (items--) {
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
			 *
			 * From here the program expects the options to be in order
			 */

			while (op_num--) {
				if (!strcmp(value, "NO_OPTION"))
					op_len += 0;

				/* Source Link Layer address */
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
						/* Option length will be 8 octets unit */
						op_len += tmp * 8;
						op++;
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

				/* Prefix information */
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
						/* option length is in 8 octets uint */
						op_len += tmp * 8;
						op++;
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

				/* MTU */
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
						/* Option length will be in 8 octets uint */
						op_len += tmp * 8;
						op++;
					}
					else
						goto err;

					/* 2-Bytes Reserverd */
					op += 2;

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
				else
					goto err;

				if (op_num && pgen_parse_option(fp, option, value))
					goto err;
				if (op_num && strcmp(option, "NDISC_RA_OPTION"))
					goto err;
			}
		}
		else
			goto err;
	}

	/* length_of_packet(12) + op_len */
	return (cp_cur + 12 + op_len);

err:
	PGEN_INFO("Error while writing ND-RA packet");
	return NULL;
}

/**
 * @param	fp		file pointer to the configuration file
 * @param	cp_cur	the packet buffer
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes ICMPv6 Router Solicitation packet
 */
char* pgen_ndisc_rs_writer(FILE *fp, char *cp_cur) {
	struct ndisc_rs_pkt *pkt = (struct ndisc_rs_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	char *op;

	/**
	 * Having 1 item
	 * 1. Option - variable length
	 */
	int32_t tmp, op_len = 0;

	if (pgen_parse_option(fp, option, value))
		goto err;

	/* Program expects the option to be in order */
	if (!strcmp(option, "NDISC_RS_OPTION")) {
		if (!strcmp(value, "NO_OPTION"))
			op_len += 0;

		/* Source Link Layer address and the only known option */
		else if (!strcmp(value, "NDISC_RS_SRC_LINK_ADDR")) {
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
				/* option length will be in 8 octets unit */
				op_len += tmp * 8;
				op++;
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
	PGEN_INFO("Error while writing ICMPv6 RS packet");
	return NULL;
}

/**
 * @param	fp		File pointer to the configuration file
 * @param	cp_cur	the packet buffer
 *
 * @returns
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes ICMPv6 Neighbour Solicitation packet
 */
char* pgen_ndisc_ns_writer(FILE *fp, char *cp_cur) {
	struct ndisc_ns_pkt *pkt = (struct ndisc_ns_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * Having only two items.
	 *
	 * 1.Target address - 16B
	 * 2.Option - Variable length
	 */
	int32_t items = 2, tmp, op_len = 0;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "NDISC_NS_TARGET_ADDR")) {
			if (ip6_writer(pkt->target_addr, value))
				goto err;
		}
		else if (!strcmp(option, "NDISC_NS_OPTION")) {
			/* Program expects the option to be in order */
			if (!strcmp(value, "NO_OPTION"))
				op_len += 0;

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
				op_len += tmp * 8;
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
	PGEN_INFO("Error while writing ICMPv6 NS packet");
	return NULL;
}

/**
 * @param	fp		file pointer to the configuration file
 * @param	cp_cur	the packet buffer
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes ICMPv6 Neighbour Advertisement packet
 */
char* pgen_ndisc_na_writer(FILE *fp, char *cp_cur) {
	struct ndisc_na_pkt *pkt = (struct ndisc_na_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	char *op_ptr;
	/**
	 * Totally 5 options
	 *
	 * 1. R Flag
	 * 2. S Flag
	 * 3. O Flag 
	 * 4. Target addr
	 * 5. The option
	 */
	int32_t items = 5, tmp, op_len = 0;

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
			/* Program expects the options to be in order */
			if (!strcmp(value, "NO_OPTION"))
				op_len += 0;

			/* This is only known option as of now. [RFC-4861] */
			else if (!strcmp(value, "NDISC_NA_SRC_LINK_ADDR")) {

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

				/* len in 8 octets unit */
				op_len += tmp * 8;
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
	PGEN_INFO("Error while writing ICMPv6 NA packet");
	return NULL;
}

/**
 * @param	fp		configuration file pointer
 * @param	cp_cur	the packet buffer
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes the ICMPv6 packet.
 */
char* pgen_icmp6_writer(FILE *fp, char *cp_cur) {
	struct icmp6_hdr *pkt = (struct icmp6_hdr *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	  * Three items need for an ICMPv6 header
	  *
	  * 1. Type
	  * 2. Code
	  * 3. Checksum
	  */
	int32_t hdr_items = 3;
    int32_t tmp;
	int32_t calculate_cksum = 0;

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
			/* User could give his own checksum. Could try a wrong one */
			if (pgen_store_dec(&tmp, value))
				goto err;
			/* If the user gives -1, program will calculate checksum */
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
		if (calculate_icmp6_checksum(pkt, (cp_cur - (char *)pkt), fp))
			goto err;
	}

	return cp_cur;

err:
	PGEN_INFO("Error while writing ICMPv6 packet");
	return NULL;
}
