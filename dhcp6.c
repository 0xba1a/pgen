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

struct dhcp6_pkt {
	int8_t msg_type;
	/**
	 * Transaction id
	 *
	 * Using structure for transaction id causes extra bytes because of
	 * structure padding.
	 */
	int8_t trans_f_byte;
	int8_t trans_s_byte;
	int8_t trans_t_byte;
	/*
	 * option is a place-holder. User has to be take care of the buff_size
	 */
	int8_t option;
};

char* pgen_dhcp6_writer(FILE *fp, char *cp_cur) {
	struct dhcp6_pkt *pkt = (struct dhcp6_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];

	/**
	 * Three items we need for dhcp6 packet.
	 * 1. Message type
	 * 2. Transaction ID
	 *
	 * 3. Number of options
	 */
	int32_t items=3, tmp;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "DHCP6_MSG_TYPE")) {
			if (pgen_store_num(&tmp, value))
				goto err;

			pkt->msg_type = (int8_t)tmp;
		}
		else if (!strcmp(option, "DHCP6_TRANS_ID")) {
			if (pgen_store_num(&tmp, value))
				goto err;

			pkt->trans_f_byte |= ((tmp >> 16) & 0xff);
			pkt->trans_s_byte |= ((tmp >> 8) & 0xff);
			pkt->trans_t_byte |= (tmp & 0xff);
		}
		else if (!strcmp(option, "DHCP6_OP_NUM")) {
			if (pgen_store_num(&tmp, value))
				goto err;
			//op_num = tmp;
		}
	}

	return (cp_cur + sizeof(struct dhcp6_pkt));

err:
	PGEN_INFO("Error while writing dhcp6 packet");
	PGEN_PRINT_DATA("%s\t%s\n", option, value);
	return NULL;
}
