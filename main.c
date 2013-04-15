#include "pgen.h"

int main(int argc, char **argv) {
	printf("main start\n");
	int sockfd;
	struct sockaddr_ll s_sock_addr;
	struct ifreq s_if_idx;
	struct ifreq s_if_mac;
	struct packet_data *sp_pd = NULL;
	char *cp_buff = NULL;
	struct ether_header *sp_ethr_hdr = NULL;
	struct ether_addr *sp_ethr_addr = NULL;

	/* Get the RAW socket */
	sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		perror("socket");
		goto err;
	}

	sp_pd = malloc(sizeof(struct packet_data));
	if (!sp_pd) {
		perror("malloc");
		goto err;
	}

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

	sp_ethr_hdr = (struct ether_header *) cp_buff;

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

	/* Get the index of the interface */
	memset(&s_if_idx, 0, sizeof (struct ifreq));
	strcpy(s_if_idx.ifr_name, sp_pd->if_name);
	if (ioctl(sockfd, SIOCGIFINDEX, &s_if_idx) < 0) {
		perror("ioctl, index");
		goto err;
	}

	/* Get the MAC address of the interface */
	memset(&s_if_mac, 0, sizeof(struct ifreq));
	strcpy(s_if_mac.ifr_name, sp_pd->if_name);
	if (ioctl(sockfd, SIOCGIFHWADDR, &s_if_mac) < 0) {
		perror("ioctl, hwaddr");
		goto err;
	}

	/* Set sending socket address */
	s_sock_addr.sll_ifindex = s_if_idx.ifr_ifindex;
	s_sock_addr.sll_halen = ETH_ALEN;
	sp_ethr_addr = ether_aton(sp_pd->dst_mac);
	if (!sp_ethr_addr) {
		perror("ether_aton");
		goto err;
	}
	memcpy(s_sock_addr.sll_addr, sp_ethr_addr, ETH_ALEN);

	if (sendto(sockfd, cp_buff, sp_pd->buff_size, 0,
				(struct sockaddr *)&s_sock_addr, 
				sizeof(struct sockaddr_ll)) < 0) {
		perror("sendto");
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
