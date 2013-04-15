#include "pgen.h"

/* These values need be finalized later */
#define MAX_LINE_LENGTH 200

int set_option(struct packet_data *sp_pd, char *option, char* value) {

	printf("option : %s\t value : %s\n", option, value);

	if (!strcmp(option, "BUFF_SIZE")) {
		errno = 0;
		sp_pd->buff_size = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid BUFF_SIZE value\n");
			goto err;
		}
	}
	else if (!strcmp(option, "IF_NAME")) {
		strcpy(sp_pd->if_name, value);
	}
	else if (!strcmp(option, "PK_DST_MAC")) {
		strcpy(sp_pd->pk_dst_mac, value);
	}
	else if (!strcmp(option, "SRC_MAC")) {
		strcpy(sp_pd->src_mac, value);
	}
	else if (!strcmp(option, "DST_MAC")) {
		strcpy(sp_pd->dst_mac, value);
	}
	else if (!strcmp(option, "ETHR_TYPE")) {
		errno = 0;
		sp_pd->ether_type = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ETHR_TYPE value\n");
			goto err;
		}
	}
	else {
		fprintf(stderr, "Invalid Option\n");
		goto err;
	}

	return 0;

err:
	return -1;
}

int parse_conf_file(struct packet_data *sp_pd) {
	FILE *fp = NULL;
	char line[MAX_LINE_LENGTH];
	char *option;
	char *value;
	char *c = NULL;

	fp = fopen(sp_pd->conf_file, "r");
	if (!fp) {
		perror("fopen");
		goto err;
	}

	while (fscanf(fp, "%s", line) != EOF) {
		option = line;

		/* Ignore comment lines */
		if (line[0] == '#') {
			char c;
			while (fscanf(fp, "%c", &c) != EOF)
				if (c == '\n')
					break;
			continue;
		}
		
		c = strchr(line, '=');
		if (!c) {
			perror("strchr");
			goto err;
		}
		
		value = c + 1;
		*c = '\0';
		c = strchr(value, '\n');
		if (c)
			*c = '\0';

		if (set_option(sp_pd, option, value)) {
			fprintf(stderr, "%s - Invalide option\n", option);
			goto err;
		}
	}

	return 0;
err:
	return -1;
}
