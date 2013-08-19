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

/**
 * @param	fp		file pointer for the configuration file
 * @param	cp_cur	The packet buffer
 *
 * @return
 *			0		Success
 *			-1		Failure
 *
 * @Description
 *		This function fills the packet buffer with user configured values.
 * It actually writes an ARP packet in the buffer.
 */
char* pgen_arp_writer(FILE *fp, char *cp_cur) {
	struct arp_packet *pkt = (struct arp_packet *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * Totally 9 items need to build or actually fill in an ARP packet
	 *
	 * 1. Hardware addr type
	 * 2. Hardware addr length
	 * 3. Protocol addr type
	 * 4. Protocol addr length
	 * 5. Operation code [request/reply]
	 * 6. Source Hardware addr
	 * 7. Source IP addr
	 * 8. Destination Hardware addr
	 * 9. Destination IP addr
   	 */
	int32_t i = 9, tmp;

	while (i--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "ARP_HW_TYPE")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->hw_type = htons(tmp);
		}
		else if (!strcmp(option, "ARP_HW_LEN")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->hw_len = (uint8_t)tmp;
		}
		else if (!strcmp(option, "ARP_PROTO_TYPE")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->proto_type = htons(tmp);
		}
		else if (!strcmp(option, "ARP_PROTO_LEN")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->proto_len = (uint8_t)tmp;
		}
		else if (!strcmp(option, "ARP_OPCODE")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->op = htons(tmp);
		}
		else if (!strcmp(option, "ARP_SRC_MAC")) {
			if (mac_writer(pkt->src_mac, value))
				goto err;
		}
		else if (!strcmp(option, "ARP_SRC_IP")) {
			if (ip4_writer(pkt->src_ip, value))
				goto err;
		}
		else if (!strcmp(option, "ARP_DST_MAC")) {
			if (mac_writer(pkt->dst_mac, value))
				goto err;
		}
		else if (!strcmp(option, "ARP_DST_IP")) {
			if (ip4_writer(pkt->dst_ip, value))
				goto err;
		}
		else {
			PGEN_INFO("Unknown ARP option");
			goto err;
		}
	}

	return (cp_cur + sizeof(struct arp_packet));

err:
	PGEN_INFO("Error while writing ARP packet");
	return NULL;
}
