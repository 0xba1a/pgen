#include "pgen.h"

struct icmp6_hdr{
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
};

struct echo6_pkt {
	uint16_t identifier;
	uint16_t seq_num;
	uint8_t data;
};

char* pgen_echo6_writer(FILE *fp, char *cp_cur) {
	struct echo6_pkt *pkt = (struct echo6_pkt *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	int items = 3, tmp, len;

	while (items--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "echo6_IDENTIFIER")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->identifier = (uint16_t)tmp;
		}
		else if (!strcmp(option, "echo6_SEQ")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->identifier = (uint16_t)tmp;
		}
		else if (!strcmp(option, "echo6_DATA")) {
			if (!strcmp(value, "NO_DATA"))
				continue;
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

char* pgen_icmp6_writer(FILE *fp, char *cp_cur) {
	struct icmp6_hdr *pkt = (struct icmp6_hdr *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	int hdr_items = 3, tmp;

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
	else
		goto err;

	if (cp_cur == NULL)
		goto err;

	return cp_cur;

err:
	return NULL;
}
