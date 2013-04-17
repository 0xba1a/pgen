#include "pgen.h"

struct ether_header {
	char ether_dhost[6];
	char ether_shost[6];
	unsigned short ether_type;
};

char* pgen_ethr_hdr_writer(struct packet_data *sp_pd, char *cp_cur) {

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

err:
	return NULL;
}
