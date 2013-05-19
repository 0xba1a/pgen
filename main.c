#include "pgen.h"

/* It starts exactly from here */
int main(int argc, char **argv) {
	FILE *fp;
	int buff_size;
	char if_name[IFNAMSIZ];
	char dst_mac[CHAR_MAC_LEN];
	char *cp_buff = NULL;
	char *cp_cur = NULL;
	char option[MAX_OPTION_LEN];
	char value[MAX_VALUE_LEN];
	char conf_file[PATH_MAX];

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
	if (pgen_parse_option(fp, option, value))
		goto err;
	if (strcmp(option, "BUFF_SIZE"))
		goto err;
	if (pgen_store_dec(&buff_size, value))
		goto err;

	/* Get interface name */
	if (pgen_parse_option(fp, option, value))
		goto err;
	if (strcmp(option, "IF_NAME"))
		goto err;
	if (!strcpy(if_name, value))
		goto err;
	if (validate_if(if_name))
		goto err;

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

	/* write the data packet */
	while (pgen_parse_option(fp, option, value) != EOF) {
		if (!strcmp(option, "ETHER_HEADER")) {
			cp_cur = pgen_ethr_hdr_writer(fp, cp_cur);
		}
		else if (!strcmp(option, "ARP")) {
			cp_cur = pgen_arp_writer(fp, cp_cur);
		}
		else if (!strcmp(option, "IPV6")) {
			cp_cur = pgen_ipv6_writer(fp, cp_cur);
		}
		else {
			printf("Unknown option\n");
			goto err;
		}
		if (!cp_cur)
			goto err;
	}


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
	free(cp_buff);

	return -1;
}
