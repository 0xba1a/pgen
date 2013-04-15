#include "pgen.h"
#include "ether.h"


/* It starts exactly from here */
int main(int argc, char **argv) {
	int sockfd, opt;
	struct sockaddr_ll s_sock_addr;
	struct ifreq s_if_idx;
	struct ifreq s_if_mac;
	struct packet_data *sp_pd = NULL;
	struct ether_addr *sp_ethr_addr = NULL;
	char *cp_buff = NULL;
	char *cp_cur = NULL;

	/* born2be root ? */
	if (getuid() != 0) {
		fprintf(stderr, "not root\n");
		goto err;
	}

	/* Get the RAW socket */
	/* TODO: maybe create the raw socket after read cmd args and parsed conf? :-) */
	sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (sockfd < 0) {
		perror("socket");
		goto err;
	}

	sp_pd = (struct packet_data *) calloc(1, sizeof(struct packet_data));
	if (!sp_pd) {
		perror("malloc");
		goto err;
	}

	/* parse command line options */
	strcpy(sp_pd->conf_file, DEF_PGEN_CONF);
	while ( (opt = getopt(argc, argv, "f:")) != -1 ) {
		switch (opt) {
			case 'f':
				strncpy(sp_pd->conf_file, optarg, PATH_MAX);
				sp_pd->conf_file[PATH_MAX-1] = '\0';
				break;
			default:
				usage();
				goto err;
		}
	}

	/* Parse the conf file */
	if (parse_conf_file(sp_pd)) {
		fprintf(stderr, "parse error\n");
		goto err;
	}

	/* Allocating the packet itself ;) */
	cp_buff = calloc(1, sp_pd->buff_size);
	if (!cp_buff) {
		perror("malloc");
		goto err;
	}

	memset(cp_buff, 0, sizeof(sp_pd->buff_size));
	cp_cur = cp_buff;

	if (!(cp_cur = ethr_hdr_writer(sp_pd, cp_cur))) {
		fprintf(stderr, "error in writing ethernet header\n");
		goto err;
	}
	
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
