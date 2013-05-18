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

#if 0

	struct ether_header *sp_ethr_hdr = NULL;

	sp_ethr_hdr = (struct ether_header *) cp_cur;

	/* Set source MAC address */
	if (mac_writer(sp_ethr_hdr->ether_shost, sp_pd->src_mac)) {
		fprintf(stderr, "ether: Source MAC copy error\n");
		goto err;
	}

	/* Set destination MAC address */
	if (mac_writer(sp_ethr_hdr->ether_dhost, sp_pd->dst_mac)) {
		fprintf(stderr, "ether: Destination MAC copy error\n");
		goto err;
	}

	/* Set packet type */
	sp_ethr_hdr->ether_type = htons(sp_pd->ether_type);

	return (cp_cur + sizeof(struct ether_header));

#endif

err:
	printf("Ether header: %s\t%s\n", option, value);
	return NULL;
}
