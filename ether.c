#include "pgen.h"

char* ethr_hdr_writer(struct packet_data *sp_pd, char *cp_cur) {

	struct ether_header *sp_ethr_hdr = NULL;
	struct ether_addr *sp_ethr_addr = NULL;

	sp_ethr_hdr = (struct ether_header *) cp_cur;

	/* Set source MAC address */
	sp_ethr_addr = ether_aton(sp_pd->src_mac);
	if (!sp_ethr_addr) {
		perror("ether_aton");
		goto err;
	}
	memcpy(sp_ethr_hdr->ether_shost, sp_ethr_addr, ETH_ALEN);

	/* Set destination MAC address */
	sp_ethr_addr = ether_aton(sp_pd->dst_mac);
	if (!sp_ethr_addr) {
		perror("ether_aton");
		goto err;
	}
	memcpy(sp_ethr_hdr->ether_dhost, sp_ethr_addr, ETH_ALEN);

	/* Set packet type */
	sp_ethr_hdr->ether_type = htons(sp_pd->ether_type);

	return ((char *)(cp_cur + sizeof(struct ether_header)));

err:
	return NULL;
}
