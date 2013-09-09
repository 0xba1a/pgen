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

struct udp_packet {
	int16_t src_port;
	int16_t dst_port;
	int16_t len;
	int16_t checksum;
	 /**
     * data is just a place holder. It only specifies the starting address.
     * UDP data will be dumped here.
     * So user should take care of the buffer size.
     */
	char data;
};

char* pgen_udp_writer(FILE *fp, char *cp_cur) {
	struct udp_packet *pkt = (struct udp_packet *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];

	/**
	 * Totally 4 items for UDP header
	 * 1. Source Port
	 * 2. Destination Port
	 * 3. Length
	 * 4. Checksum
	 *
	 * 5. UDP data
	 */
	int32_t items = 5, tmp, len;
	int32_t calculate_checksum = 0;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "UDP_SRC_PORT")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->src_port = htons(tmp);
		}
		else if (!strcmp(option, "UDP_DST_PORT")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			pkt->dst_port = htons(tmp);
		}
		else if (!strcmp(option, "UDP_LEN")) {
			if (pgen_store_num(&len, value))
				goto err;
			pkt->len = htons(len);
		}
		else if (!strcmp(option, "UDP_CHECKSUM")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			if (tmp != -1)
				pkt->checksum = htons(tmp);
			else
				calculate_checksum = 1;
		}
		else if (!strcmp(option, "UDP_DATA")) {
			if (!strcmp(value, "NO_DATA")) {
				cp_cur += sizeof(struct udp_packet);
			}
			else if (!strcmp(value, "DHCPV6")) {
				cp_cur = pgen_dhcp6_writer(fp, (char *)(&pkt->data));
			}
		}
		else {
			PGEN_INFO("Option not yet supported\n");
			goto err;
		}
	}

	if (!cp_cur)
		goto err;

	if (calculate_checksum) {
		pkt->checksum = calculate_internet_checksum((int16_t *)pkt, len,
			   fp, 0x11);
		pkt->checksum = htons(pkt->checksum);
	}

	return cp_cur;

err:
	PGEN_INFO("Error while writing UDP header\n");
	PGEN_PRINT_DATA("Option: %s\tValue: %s\n", option, value);
	return NULL;
}
