#include "pgen.h"

struct icmp6_hdr {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	void *body;
};

char* pgen_icmp6_writer(struct packet_data *sp_pd, char *cp_cur) {
	struct icmp6_hdr *pkt = (struct icmp6_hdr *)cp_cur;

	pkt->type = (uint8_t)sp_pd->icmp6_type;
	pkt->code = (uint8_t)sp_pd->icmp6_code;
	pkt->checksum = htons(sp_pd->icmp6_checksum);

	///NEED TO BE CHANGED
	return (cp_cur + (sizeof(struct icmp6_hdr)));

err:
	return NULL;
}
