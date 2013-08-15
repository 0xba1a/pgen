#include "pgen.h"

struct ether_header {
	char ether_dhost[6];
	char ether_shost[6];
	unsigned short ether_type;
};

/**
 * @param	fp		file pointer to the configuration file
 * @param	cp_cur	the packet data
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes ether-header to the packet buffer
 */
char* pgen_ethr_hdr_writer(FILE *fp, char *cp_cur) {
	struct ether_header *pkt = (struct ether_header *)cp_cur;
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/**
	 * Ether header nees 3 items
	 *
	 * 1. Destination mac address
	 * 2. Source mac address
	 * 3. Ether type. The type of the packet it holds
	 */
	int i = 3, tmp;

	while (i--) {
		if (pgen_parse_option(fp, option, value))
			goto err;
		
		if (!strcmp(option, "DST_MAC")) {
			/// validate value for mac
			if (mac_writer(pkt->ether_dhost, value))
				goto err;
		}
		else if (!strcmp(option, "SRC_MAC")) {
			/// validate value for mac
			if (mac_writer(pkt->ether_shost, value))
				goto err;
		}
		else if (!strcmp(option, "ETHR_TYPE")) {
			if (pgen_store_dec(&tmp, value))
				goto err;
			pkt->ether_type = htons(tmp);
		}
		else
			goto err;
	}
	return (cp_cur + sizeof(struct ether_header));

err:
	PGEN_INFO("Error while writing ether header");
	return NULL;
}
