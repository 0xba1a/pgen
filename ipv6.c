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

struct ipv6_packet {
	/* 
	 version 4 bits
	 traffic-class 8 bits
	 flow-label 20 bits
	 */
	int32_t ver_tc_fw;
	int16_t payload_length;
	char next_header;
	char hop_limit;
	char src[16];
	char dst[16];
};

struct hbh_packet {
	char nxt_hdr;
	char ext_len;
	char data;
};

struct dh_packet {
	char nxt_hdr;
	char ext_len;
	char data;
};

struct routing_hdr_packet {
	char nxt_hdr;
	char ext_len;
	char type;
	char seg_left;
	char data;
};

struct fragment_hdr {
	char nxt_hdr;
	char res;
	int16_t fo_res_m;
	int32_t identification;
};

/**
 * @param	fp		File pointer to the configuration value
 * @param	cp_cur	The packet buffer
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes fragment header in the packet buffer
 */
char* ipv6_fragment_hdr_writer(FILE *fp, char *cp_cur) {
	struct fragment_hdr *pkt = (struct fragment_hdr *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * Totally 4 items need for fragment header. [RFC-2460]
	 *
	 * 1. Next header
	 * 2. Fragment offset
	 * 3. M flag
	 * 4. Fragment identification
	 */
	int32_t items = 4, tmp;

	pkt->fo_res_m = 0;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "FH_NXT_HDR")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->nxt_hdr = (uint8_t)tmp;
		}
		else if (!strcmp(option, "FH_OFFSET")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->fo_res_m |= (uint16_t)(tmp << 3);
		}
		else if (!strcmp(option, "FH_M_FLAG")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->fo_res_m |= (uint16_t)(tmp & 0x1);
		}
		else if (!strcmp(option, "FH_IDENTIFICATION")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->identification = htonl(tmp);
		}
		else
			goto err;
	}
	pkt->fo_res_m = htons(pkt->fo_res_m);
	pkt->res = 0;

	return cp_cur + sizeof(struct fragment_hdr);

err:
	PGEN_INFO("Error while writing Fragment Header");
	return NULL;
}

/**
 * @param	fp		File pointer to the configuration file
 * @param	cp_cur	The packet buffer
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes IPv6 Routing header
 */
char* ipv6_routing_hdr_writer(FILE *fp, char *cp_cur) {
	struct routing_hdr_packet *pkt = (struct routing_hdr_packet *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * 5 items need for writing routing header [RFC-2460]
	 *
	 * 1. Next header
	 * 2. Header extension length
	 * 3. Routing type
	 * 4. Segments left
	 * 5. Type specific data
	 */
	int32_t items = 5, tmp, len = 0, type, oitems;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "RH_NXT_HDR")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->nxt_hdr = (uint8_t)tmp;
		}
		else if (!strcmp(option, "RH_EXT_LEN")) {
			if (pgen_store_num(&len, value))
				goto err;
			pkt->ext_len = (uint8_t)len;
		}
		else if (!strcmp(option, "RH_TYPE")) {
			if (pgen_store_num(&type, value))
				goto err;
			pkt->type = (uint8_t)type;
		}
		else if (!strcmp(option, "RH_SEG_LEFT")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->seg_left = (uint8_t)tmp;
		}
		else if (!strcmp(option, "RH_DATA")) {
			/**
			 * As of now, the only known routing header for this program is
			 * type 0 Routing Header. [RFC-2460]
			 */
			if (type == 0) {
				/**
				 * [RFC-2460]
				 * For the Type 0 Routing header, Hdr Ext Len is equal to two
				 * times the number of addresses in the header.
				 */
				oitems = len / 2;
				while (oitems) {
					if (pgen_parse_option(fp, option, value))
						goto err;
					if (strcmp(option, "RH_ADDR"))
						goto err;
					if (ip6_writer(((&pkt->data)+(((len/2)-oitems)*16)+4),
							   (const char *)value))
						goto err;
					oitems--;
				}
			}
		}
	}
	return cp_cur + 8*(len+1);

err:
	PGEN_INFO("Error while writing Routing Header");
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
 *		Writing IPv6 hop-by-hop option header
 */
char* ipv6_hbh_writer(FILE *fp, char *cp_cur) {
	struct hbh_packet *pkt = (struct hbh_packet *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * 3 items for IPv6 hop-by-hop option header
	 *
	 * 1. Next header
	 * 2. Header extension length
	 * 3. Options
	 *
	 * 4. Number of options
	 */
	int32_t items = 4, tmp, len = 0, op_num;
	char *op;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "HBH_NXT_HDR")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->nxt_hdr = (uint8_t)tmp;
		}
		else if (!strcmp(option, "HBH_HDR_EXT_LEN")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->ext_len = (uint8_t)tmp;
		}
		else if (!strcmp(option, "HBH_OPTION_NUM")) {
			if (pgen_store_num(&op_num, value))
				goto err;
		}
		else if (!strcmp(option, "HBH_OPTION")) {
			len = 0;
			op = &pkt->data;
			/**
			 * [RFC-2460]
			 * The only hop-by-hop options defined in this document are the
			 * Pad1 and PadN
			 */
			while (op_num--) {
				/* Pad-1 */
				if (!strcmp(value, "PAD1")) {
					if (pad1(op))
						goto err;
					op += 1;
					len += 1;
				}
				/* Pad-N */
				else if (!strcmp(value, "PADN")) {
					tmp = padN(fp, op);
					if (tmp < 1)
						goto err;
					op += tmp;
					len += tmp;
				}
				/* RAW option in hex */
				else if (!strcmp(value, "RAW")) {
					tmp = raw_data_writer(fp, op);
					if (tmp < 0)
						goto err;
					op += tmp;
					len += tmp;
				}
				else
					goto err;

				if (op_num) {
					if (pgen_parse_option(fp, option, value))
						goto err;

					if (strcmp(option, "HBH_OPTION"))
						goto err;
				}
			}
/*
			len = option_writer(&pkt->data, value);
			if (len < 0)
				goto err;
*/
		}
		else
			goto err;
	}
	return (cp_cur + len + 2);

err:
	PGEN_INFO("Error while writing IPv6 Hop-by-Hop option header");
	return NULL;
}

/**
 * @param	fp		file pointer to the configuration file
 * @param	cp_cur	The packet data
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes IPv6 destination option header.
 * 		Even destination header is same as like Hob-by-Hop header, having
 * different writer implementation will give better modulority.
 */
char* ipv6_destination_hdr_writer(FILE *fp, char *cp_cur) {
    struct dh_packet *pkt = (struct dh_packet *)cp_cur;
    char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * 3 options need for IPv6 Destination option header
	 *
	 * 1. Next header
	 * 2. Header extension length
	 * 3. Option
	 *
	 * 4. Number of options
	 */
    int32_t items = 4, tmp, len = 0, op_num;
	char *op;

    while (items--) {
        if (pgen_parse_option(fp, option, value))
            goto err;

        if (!strcmp(option, "DH_NXT_HDR")) {
            if (pgen_store_num(&tmp, value))
                goto err;
            pkt->nxt_hdr = (uint8_t)tmp;
        }
        else if (!strcmp(option, "DH_HDR_EXT_LEN")) {
            if (pgen_store_num(&tmp, value))
                goto err;
            pkt->ext_len = (uint8_t)tmp;
        }
		else if (!strcmp(option, "DH_OPTION_NUM")) {
			if (pgen_store_num(&op_num, value))
				goto err;
		}
        else if (!strcmp(option, "DH_OPTION")) {
			len = 0;
			op = &pkt->data;
			/**
			 * [RFC-2460]
			 * The only destination options defined in this document are
			 * the Pad1 and PadN
			 */

			while (op_num--) {
				/* Pad-1 */
				if (!strcmp(value, "PAD1")) {
					if (pad1(op))
						goto err;
					len += 1;
					op += 1;
				}
				/* Pad-N */
				else if (!strcmp(value, "PADN")) {
					tmp = padN(fp, op);
					if (tmp < 0)
						goto err;
					op += tmp;
					len += tmp;
				}
				/* RAW */
				else if (!strcmp(value, "RAW")) {
					tmp = raw_data_writer(fp, op);
					if (tmp < 0)
						goto err;
					op += tmp;
					len += tmp;
				}
				/* Unknown option */
				else
					goto err;

				if (op_num) {
					if (pgen_parse_option(fp, option, value))
						goto err;

					if (strcmp(option, "DH_OPTION"))
						goto err;
				}
			}
        }
        else
            goto err;
    }
    return (cp_cur + len + 2);

err:
	PGEN_INFO("Error while writing IPv6 Destination Option header");
    return NULL;
}

/**
 * @param	fp		File pointer to the configuration file
 * @param	cp_cur	The packet buffer
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes IPv6 header
 */
char* pgen_ipv6_writer(FILE *fp, char *cp_cur) {
	struct ipv6_packet *pkt = (struct ipv6_packet *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/** 
	 * Totally we have 9 items in IPv6 header.
	 *
	 * items needed for packet - 8.
	 * 1. Version [Of course It is IPv'6']
	 * 2. Traffic class
	 * 3. Flow label
	 * 4. Payload length
	 * 5. Next header
	 * 6. Hop limit
	 * 7. Source IPv6 address
	 * 8. Destination IPv6 address
	 *
	 * And one for the program
	 * 1. Number of extension headers that follows IPv6 header
	 */
	int hdr_items = 9, tmp, ext_hdrs;

	pkt->ver_tc_fw = 0;

	while (hdr_items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "IPV6_VERSION")) {
			/**
			 * [RFC-2460]
			 * 4-bit Internet Protocol version number = 6.
			 */
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->ver_tc_fw |= tmp << 28;
		}
		else if (!strcmp(option, "IPV6_TRAFFIC_CLASS")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->ver_tc_fw |= tmp << 20;
		}
		else if (!strcmp(option, "IPV6_FLOW_LABEL")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->ver_tc_fw |= (tmp & 0xfffff);
		}
		else if (!strcmp(option, "IPV6_PAYLOAD_LENGTH")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->payload_length = htons(tmp);
		}
		else if (!strcmp(option, "IPV6_NEXT_HEADER")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->next_header = (uint8_t)tmp;
		}
		else if (!strcmp(option, "IPV6_HOP_LIMIT")) {
			if (pgen_store_num(&tmp, value))
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
			/* Number of extension headers that follows IPv6 header */
			if (pgen_store_num(&ext_hdrs, value))
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

		/**
		 * Five known extension headers [RFC-2460]
		 * 1. Hop-by-Hop option header
		 * 2. Routing header
		 * 3. Fragment header
		 * 4. Destination option header
		 * 5. No next header
		 */
		if (!strcmp(option, "HOP_BY_HOP")) {
			cp_cur = ipv6_hbh_writer(fp, cp_cur);
		}
		else if (!strcmp(option, "ROUTING_HEADER")) {
			cp_cur = ipv6_routing_hdr_writer(fp, cp_cur);
		}
		else if (!strcmp(option, "FRAGMENT_HEADER")) {
			cp_cur = ipv6_fragment_hdr_writer(fp, cp_cur);
		}
		else if (!strcmp(option, "DESTINATION_HEADER")) {
			cp_cur = ipv6_destination_hdr_writer(fp, cp_cur);
		}
		/* No next header needs nothing other than next header value of 59 */
		else
			goto err;

		if (cp_cur == NULL)
			goto err;
	}

	return cp_cur;

err:
	PGEN_INFO("Error while writing IPv6 header/its extension header");
	PGEN_PRINT_DATA("%s\t%s\n", option, value);
	return NULL;
}
