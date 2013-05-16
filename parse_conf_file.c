#include "pgen.h"

/* These values need be finalized later */
#define MAX_LINE_LENGTH 200

int set_option(struct packet_data *sp_pd, const char *option,
	   const char* value) {

	///printf("%s\t : %s\n", option, value);

	/* Common information */
	if (!pgen_strcmp(option, "BUFF_SIZE")) {
		errno = 0;
		sp_pd->buff_size = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid BUFF_SIZE value\n");
			goto err;
		}
	}

	/* Sending socket related info */
	else if (!pgen_strcmp(option, "IF_NAME")) {
		strcpy(sp_pd->if_name, value);
	}
	else if (!pgen_strcmp(option, "PK_DST_MAC")) {
		strcpy(sp_pd->pk_dst_mac, value);
	}

	/* Ethernet related info */
	else if (!pgen_strcmp(option, "ETHER_HEADER")) {
		errno = 0;
		sp_pd->ether_hdr = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ETHER_HEADER type\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "SRC_MAC")) {
		strcpy(sp_pd->src_mac, value);
	}
	else if (!pgen_strcmp(option, "DST_MAC")) {
		strcpy(sp_pd->dst_mac, value);
	}
	else if (!pgen_strcmp(option, "ETHR_TYPE")) {
		errno = 0;
		sp_pd->ether_type = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ETHR_TYPE value\n");
			goto err;
		}
	}

	/* ARP protocol related information */
	else if (!pgen_strcmp(option, "ARP")) {
		errno = 0;
		sp_pd->arp = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ARP value\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ARP_HW_TYPE")) {
		errno = 0;
		sp_pd->arp_hw_type = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ARP_HW_TYPE\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ARP_PROTO_TYPE")) {
		errno = 0;
		sp_pd->arp_proto_type = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ARP_PROTO_TYPE\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ARP_HW_LEN")) {
		errno = 0;
		sp_pd->arp_hw_len = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ARP_HW_LEN\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ARP_PROTO_LEN")) {
		errno = 0;
		sp_pd->arp_proto_len = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ARP_PROTO_LEN\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ARP_OPCODE")) {
		errno = 0;
		sp_pd->arp_opcode = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ARP_OPCODE\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ARP_SRC_MAC")) {
		strcpy(sp_pd->arp_src_mac, value);
	}
	else if (!pgen_strcmp(option, "ARP_SRC_IP")) {
		strcpy(sp_pd->arp_src_ip, value);
	}
	else if (!pgen_strcmp(option, "ARP_DST_IP")) {
		strcpy(sp_pd->arp_dst_ip, value);
	}
	else if (!pgen_strcmp(option, "ARP_DST_MAC")) {
		strcpy(sp_pd->arp_dst_mac, value);
	}

	/* IPv6 header related information */
	else if (!pgen_strcmp(option, "IPV6")) {
		errno = 0;
		sp_pd->ipv6 = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid IPv6 code\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "IPV6_VERSION")) {
		errno = 0;
		sp_pd->ipv6_version = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid IPV6_VERSION\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "IPV6_TRAFFIC_CLASS")) {
		errno = 0;
		sp_pd->ipv6_traffic_class = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid IPV6_TRAFFIC_CLASS\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "IPV6_FLOW_LABEL")) {
		errno = 0;
		sp_pd->ipv6_flow_label = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid IPV6_FLOW_LABEL\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "IPV6_PAYLOAD_LENGTH")) {
		errno = 0;
		sp_pd->ipv6_payload_length = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid IPV6_PAYLOAD_LENGTH\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "IPV6_NEXT_HEADER")) {
		errno = 0;
		sp_pd->ipv6_next_header = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid IPV6_NEXT_HEADER\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "IPV6_HOP_LIMIT")) {
		errno = 0;
		sp_pd->ipv6_hop_limit = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid IPV6_HOP_LIMIT\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "IPV6_SRC_ADDR")) {
		strcpy(sp_pd->ipv6_src, value);
	}
	else if (!pgen_strcmp(option, "IPV6_DST_ADDR")) {
		strcpy(sp_pd->ipv6_dst, value);
	}

	/* ICMPv6 header information */
	else if (!pgen_strcmp(option, "ICMP6")) {
		errno = 0;
		sp_pd->icmp6 = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ICMP6\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ICMP6_TYPE")) {
		errno = 0;
		sp_pd->icmp6_type = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ICMP6_TYPE\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ICMP6_CODE")) {
		errno = 0;
		sp_pd->icmp6_code = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ICMP6_CODE\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ICMP6_CHECKSUM")) {
		errno = 0;
		sp_pd->icmp6_checksum = strtol(value, NULL, 10);
		if (errno) {
			fprintf(stderr, "Invalid ICMP6_CHECKSUM\n");
			goto err;
		}
	}
	else if (!pgen_strcmp(option, "ICMP6_BODY_TYPE")) {
	}

	/* OR ELSE ERROR */
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
