#include "pgen.h"

/* It starts exactly from here */
int main(int argc, char **argv) {
	struct packet_data *sp_pd = NULL;
	struct ether_addr *sp_ethr_addr = NULL;
	char *cp_buff = NULL;
	char *cp_cur = NULL;

	sp_pd = malloc(sizeof(struct packet_data));
	if (!sp_pd) {
		perror("malloc");
		goto err;
	}
	memset(sp_pd, 0, sizeof(struct packet_data));

	/* Choose the conf file */
	if (argc < 2)
		strcpy(sp_pd->conf_file, DEF_PGEN_CONF);
	else if (argc == 2)
		strcpy(sp_pd->conf_file, argv[1]);
	else {
		usage();
		goto err;
	}

	/* Parse the conf file */
	if (parse_conf_file(sp_pd)) {
		fprintf(stderr, "parse error\n");
		goto err;
	}

	/* Allocating the packet itself ;) */
	cp_buff = malloc(sp_pd->buff_size);
	if (!cp_buff) {
		perror("malloc");
		goto err;
	}
	memset(cp_buff, 0, sizeof(sp_pd->buff_size));
	cp_cur = cp_buff;

	/* Ethernet portion */
	if (sp_pd->ether_hdr) {
		if (!(cp_cur = pgen_ethr_hdr_writer(sp_pd, cp_cur))) {
			fprintf(stderr, "error in writing ethernet header\n");
			goto err;
		}
	}

	/* ARP protion */
	if (sp_pd->arp) {
		if (!(cp_cur = pgen_arp_hdr_writer(sp_pd, cp_cur))) {
			fprintf(stderr, "error in arp writing\n");
			goto err;
		}
	}
	
	/* Get the index of the interface */
	/* Send the packet in wire */
	if (send_packet(sp_pd, cp_buff)) {
		fprintf(stderr, "Error while sending packet\n");
		goto err;
	}

	return 0;

err:
	fprintf(stderr, "ERROR CASE\n");
	/* free will accept NULL */
	free(sp_pd);
	free(cp_buff);

	return -1;
}
