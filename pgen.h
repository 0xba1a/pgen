#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <errno.h>
#include <linux/limits.h>

#define DEF_PGEN_CONF "/etc/pgen.conf"

struct packet_data {
	char conf_file[PATH_MAX];
	size_t buff_size;
	int ether_type;
	char if_name[IFNAMSIZ];
	char src_mac[17];
	char dst_mac[17];
};

void usage();
int parse_conf_file(struct packet_data *);
