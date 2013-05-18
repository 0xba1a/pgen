#include "pgen.h"

struct ether_header {
	char ether_dhost[6];
	char ether_shost[6];
	unsigned short ether_type;
};

char* pgen_ethr_hdr_writer(FILE *fp, char *cp_cur) {
	struct ether_header *pkt = (struct ether_header *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/* 3 ether options from conf file */
	int i = 3, tmp;

	while (i--) {
		if (pgen_parse_option(fp, option, value))
			goto err;
		
		if (!strcmp(option, "DST_MAC")) {
			/// validate value for mac
			if (mac_writer(pkt->ether_dhost, value))
				goto err;
		}
		else if (!strcmp(option, "SRC_MAC")) {
			/// validate value for mac
			if (mac_writer(pkt->ether_shost, value))
				goto err;
		}
		else if (!strcmp(option, "ETHR_TYPE")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->ether_type = htons(tmp);
		}
		else
			goto err;
	}
	return (cp_cur + sizeof(struct ether_header));

err:
	printf("Ether header: %s\t%s\n", option, value);
	return NULL;
}
