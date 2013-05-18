#include "pgen.h"

/* It starts exactly from here */
int main(int argc, char **argv) {
	struct packet_data *sp_pd = NULL; ///remove it
	FILE *fp;
	int buff_size;
	char if_name[IFNAMSIZ];
	char dst_mac[CHAR_MAC_LEN];
	char *cp_buff = NULL;
	char *cp_cur = NULL;
	char option[MAX_OPTION_LEN];
	char value[MAX_VALUE_LEN];
	char conf_file[PATH_MAX];

	///remove it
	sp_pd = malloc(sizeof(struct packet_data));
	if (!sp_pd) {
		perror("malloc");
		goto err;
	}
	memset(sp_pd, 0, sizeof(struct packet_data));

	/* Choose the conf file */
	if (argc < 2)
		strcpy(conf_file, DEF_PGEN_CONF);
	else if (argc == 2)
		strcpy(conf_file, argv[1]);
	else {
		usage();
		goto err;
	}

	/* Open Conf file */
	fp = fopen(conf_file, "r");
	if (!fp) {
		perror("Opening conf file");
		return -1;
	}

	/* Get buffer size */
	if (pgen_parse_option(fp, option, value)) {
		goto err;
	}
	if (strcmp(option, "BUFF_SIZE")) {
		goto err;
	}
	if (pgen_store_dec(&buff_size, value)) {
		goto err;
	}

	/* Get interface name */
	if (pgen_parse_option(fp, option, value)) {
		goto err;
	}
	if (strcmp(option, "IF_NAME")) {
		goto err;
	}
	if (!strcpy(if_name, value)) {
		goto err;
	}

	/* Get recipient mac address */
	if (pgen_parse_option(fp, option, value))
		goto err;
	if (strcmp(option, "PK_DST_MAC"))
		goto err;
	if (!strcpy(dst_mac, value))
		goto err;

	/* Allocating the packet itself ;) */
	cp_buff = malloc(buff_size);
	if (!cp_buff) {
		perror("malloc");
		goto err;
	}
	memset(cp_buff, 0, sizeof(buff_size));
	cp_cur = cp_buff;

	while (pgen_parse_option(fp, option, value) != EOF) {
		if (!pgen_strcmp(option, "ETHER_HEADER")) {
			cp_cur = pgen_ethr_hdr_writer(fp, cp_cur);
		}
		if (!cp_cur)
			goto err;
	}


#if 0
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

	/* IPv6 part */
	if (sp_pd->ipv6) {
		if (!(cp_cur = pgen_ipv6_hdr_writer(sp_pd, cp_cur))) {
			fprintf(stderr, "error in IPv6 writing\n");
			goto err;
		}
	}

	/* ICMP6 part */
	if (sp_pd->icmp6) {
		if (!(cp_cur = pgen_icmp6_writer(sp_pd, cp_cur))) {
			fprintf(stderr, "error in ICMPv6 writing\n");
			goto err;
		}
	}
#endif

	/* Get the index of the interface */
	/* Send the packet in wire */
	if (send_packet(if_name, dst_mac, cp_buff, buff_size)) {
		fprintf(stderr, "Error while sending packet\n");
		goto err;
	}

	return 0;

err:
	fprintf(stderr, "ERROR CASE\n");
	fprintf(stderr, "option: %s\tvalue: %s\n", option, value);
	fclose(fp);
	/* free will accept NULL */
	free(sp_pd);
	free(cp_buff);

	return -1;
}
