#include <net/if_arp.h>

#include "pgen.h"

struct arp_packet {
	unsigned short hw_type;
	unsigned short proto_type;
	unsigned char hw_len;
	unsigned char proto_len;
	unsigned short op;
	unsigned char src_mac[6];
	unsigned char src_ip[4];
	unsigned char dst_mac[6];
	unsigned char dst_ip[4];
};

/**
 * @param	fp		file pointer for the configuration file
 * @param	cp_cur	The packet buffer
 *
 * @return
 *			0		Success
 *			-1		Failure
 *
 * @Description
 *		This function fills the packet buffer with user configured values.
 * It actually writes an ARP packet in the buffer.
 */
char* pgen_arp_writer(FILE *fp, char *cp_cur) {
	struct arp_packet *pkt = (struct arp_packet *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * Totally 9 items need to build or actually fill in an ARP packet
	 *
	 * 1. Hardware addr type
	 * 2. Hardware addr length
	 * 3. Protocol addr type
	 * 4. Protocol addr length
	 * 5. Operation code [request/reply]
	 * 6. Source Hardware addr
	 * 7. Source IP addr
	 * 8. Destination Hardware addr
	 * 9. Destination IP addr
   	 */
	int32_t i = 9, tmp;

	while (i--) {
		if (pgen_parse_option(fp, option, value))
			goto err;

		if (!strcmp(option, "ARP_HW_TYPE")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->hw_type = htons(tmp);
		}
		else if (!strcmp(option, "ARP_HW_LEN")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->hw_len = (uint8_t)tmp;
		}
		else if (!strcmp(option, "ARP_PROTO_TYPE")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->proto_type = htons(tmp);
		}
		else if (!strcmp(option, "ARP_PROTO_LEN")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->proto_len = (uint8_t)tmp;
		}
		else if (!strcmp(option, "ARP_OPCODE")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->op = htons(tmp);
		}
		else if (!strcmp(option, "ARP_SRC_MAC")) {
			if (mac_writer(pkt->src_mac, value))
				goto err;
		}
		else if (!strcmp(option, "ARP_SRC_IP")) {
			if (ip4_writer(pkt->src_ip, value))
				goto err;
		}
		else if (!strcmp(option, "ARP_DST_MAC")) {
			if (mac_writer(pkt->dst_mac, value))
				goto err;
		}
		else if (!strcmp(option, "ARP_DST_IP")) {
			if (ip4_writer(pkt->dst_ip, value))
				goto err;
		}
		else {
			PGEN_INFO("Unknown ARP option");
			goto err;
		}
	}

	return (cp_cur + sizeof(struct arp_packet));

err:
	PGEN_INFO("Error while writing ARP packet");
	return NULL;
}
