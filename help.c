/**
 * This file is part of pgen, a packet generator tool.
 * Copyright (C) 2013  Balakumaran Kannan <kumaran.4353@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "pgen.h"

/**
 * @Description
 * 		Tells how to use pgen while you are using it wrong
 */
void usage() {
	PGEN_INFO("Usage: pgen [conf_file]\n");
}

/**
 * @param	s1	Destination pointer
 * @param	s2	Source pointer
 *
 * @returns
 *			0	Success
 *			!0	Error
 *
 * @Description
 * 		As strcmp is vulnurable, we are having a wrapper function over strncmp.
 * 	But anyway it is not used much in this project (ridiculous!).
 */
int32_t pgen_strcmp(const char *s1, const char *s2) {
	return strncmp(s1, s2, strlen(s2) + 1);
}

/**
 * @param	pkt		The packet buffer
 * @param	len		length of the ICMPv6 packet
 * @param	fp		file pointer to the configuration file
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		This function reads the ICMPv6 packet, calculates checksum and fills
 * the checksum field in the packet.
 * [RFC-4443]
 * The checksum is the 16-bit one's complement of the one's complement sum of
 * the entire ICMPv6 message, starting with the ICMPv6 message type field, and
 * prepended with a "pseudo-header" of IPv6 header fields...
 */
/* NOT FIXED */
int16_t calculate_internet_checksum(int16_t *pkt, int32_t len,
	   FILE *fp, int32_t type) {
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	uint32_t checksum = 0;
	int32_t init_pos, pos;
	char src[16] = {0}, dst[16] = {0};
	int32_t i;

	/* store the current position of cursur in the conf file */
	init_pos = ftell(fp);
	if (init_pos < 0)
		goto err;

	/* Move cursur to the starting of conf file */
	if (fseek(fp, 0, SEEK_SET))
		goto err;

	/* Find src and dst addresses that immediately above from current pos */
	do {
		if (pgen_parse_option(fp, option, value))
			goto err;

		pos = ftell(fp);

		if (!strcmp(option, "IPV6_SRC_ADDR")) {
			if (ip6_writer(src, value))
				goto err;
		}
		else if (!strcmp(option, "IPV6_DST_ADDR")) {
			if (ip6_writer(dst, value))
				goto err;
		}
	} while ((pos != -1) && (pos < init_pos));

	if (pos == -1)
		goto err;

	/* Process ipv6 src and dst addresses for checksum */
	for (i = 0; i < 16; i += 2) {
		checksum += (((src[i] & 0xff) << 8) | (src[i+1] & 0xff));
		checksum += (((dst[i] & 0xff) << 8) | (dst[i+1] & 0xff));
	}

	/* process length of the icmpv6 message */	
	checksum += len;

	/* Process packet type. Packet type is always icmpv6 */
	checksum += 0x3a;

	/* Process icmpv6 packet data */
	while (len > 1) {
		checksum += htons(*pkt);
		pkt++;
		len -= 2;
	}
	if (len > 0)
		checksum += ((*(char *)pkt) << 8);

	/* Make it into 16 bits */
	while (checksum >> 16 != 0)
		checksum = (checksum & 0xffff) + (checksum >> 16);

	/* One's complement */
	checksum = ~checksum;

	/* Restore the file position for furthur processing */
	if (fseek(fp, init_pos, SEEK_SET))
		goto err;

	return (int16_t)checksum;

err:
	PGEN_INFO("Error while writing ICMPv6 checksum");
	exit(-1);
}

/**
 * @param	if_name		name of the interface by which the packet has to be
 *						sent.
 * @param	dst_mac		Mac address of the destination node
 * @param	cp_buff		The packet buffer
 * @param	buff_size	Size of the packet buffer
 *
 * @return
 *			0		Success
 *			-1		Failure
 *
 * @Description
 *		Here comes the end. This function puts the packet buffer into wire.
 */
int32_t send_packet(const char *if_name, const char *dst_mac, const char *cp_buff,
		const int32_t buff_size) {
	int32_t sockfd;
	struct sockaddr_ll s_sock_addr;
	struct ifreq s_if_idx;
	struct ifreq s_if_mac;

	/* Get the RAW socket. Must have root permission */
    sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
		PGEN_ERROR("socket creation failed", errno);
        goto err;
    }

	/* Get the index of the interface */
    memset(&s_if_idx, 0, sizeof (struct ifreq));
    strcpy(s_if_idx.ifr_name, if_name);
    if (ioctl(sockfd, SIOCGIFINDEX, &s_if_idx) < 0) {
		PGEN_ERROR("ioctl to get if index failed", errno);
        goto err;
    }

    /* Get the MAC address of the interface */
    memset(&s_if_mac, 0, sizeof(struct ifreq));
    strcpy(s_if_mac.ifr_name, if_name);
    if (ioctl(sockfd, SIOCGIFHWADDR, &s_if_mac) < 0) {
		PGEN_ERROR("ioctl to get if mac failed", errno);
        goto err;
    }

    /* Set sending socket address */
    s_sock_addr.sll_ifindex = s_if_idx.ifr_ifindex;
    s_sock_addr.sll_halen = ETH_ALEN;
    if (mac_writer((char *)s_sock_addr.sll_addr, dst_mac)) {
		PGEN_INFO("dst mac writing error");
        goto err;
    }

	/* Ok. Now send it */
	if (sendto(sockfd, cp_buff, buff_size, 0,
                (struct sockaddr *)&s_sock_addr,
                sizeof(struct sockaddr_ll)) < 0) {
		PGEN_ERROR("sendto failed", errno);
        goto err;
    }
	return 0;

err:
	return -1;
}

/**
 * @param	mac		The mac address that to be validated
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Checks whether the given mac address is valid.
 */
int validate_mac(const char *mac) {
	int i;

	if (strlen(mac) != 17)
		goto err;

	for (i = 0; i < 17; i++) {
		if ((((mac[i] >= 'A') && (mac[i] <= 'F')) ||
				((mac[i] >= 'a') && (mac[i] <= 'f')) ||
				((mac[i] >= '0') && (mac[i] <= '9')))
				&& ((i+1) % 3 != 0))
			continue;
		else if ((mac[i] == ':') && ((i+1)%3 == 0))
			continue;
		else
			goto err;
	}
	return 0;

err:
	PGEN_INFO("Mac validation failed");
	PGEN_PRINT_DATA("%s\n", mac);
	return -1;
}

/**
 * @param	dst		Destination pointer where the resulting mac address
 *					will be stored
 * @param	src		Source character pointer in which mac address to be
 *					converted is passed
 *
 * @return
 *			0		Success
 *			-1		Failure
 *
 * @Description
 *			Converts mac from string form into binary form and stores in dst
 */
int32_t mac_writer(char *dst, const char *src) {
    int32_t seg = 0;
    char ind;
    int32_t i, j = 0;

	if (!dst || !src) {
		PGEN_INFO("Arguments NULL check failed");
		goto err;
	}

	if (validate_mac(src))
		goto err;

    for (i = 0; i < 17; i++) {
        ind = src[i];
        if (ind >= '0' && ind <= '9')
            seg = (seg * 16) + (ind - '0');
        else if (ind >= 'a' && ind <= 'f')
            seg = (seg * 16) + (ind - 'a') + 10;
		else if (ind >= 'A' && ind <= 'F')
			seg = (seg * 16) + (ind - 'A') + 10;
        else if (ind == ':') {
            dst[j++] = (unsigned char) seg;
            seg = 0;
        }
        else
			goto err;
    }
	dst[j] = (unsigned char) seg;
    return 0;

err:
	PGEN_INFO("mac_writer returns error");
	return -1;
}

/**
 * @param	dst		destination pointer where binary IPv4 address will be
 *					stored
 * @param	src		source pointer in which string form of IPv4 address is
 *					passed
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		This function converts string form of IPv4 address into binary form
 * and stores that in dst. It is simply a wrapper over inet_pton
 */
int32_t ip4_writer(char *dst, const char *src) {

	if (inet_pton(AF_INET, src, dst) == 0) {
		PGEN_INFO("Invalid IP address");
		return -1;
	}
	return 0;

	/* Could be helpful in future */
#if 0
    int32_t seg = 0;
    char ind;
    int32_t i, j = 0;
    
    for (i = 0; i < 15; i++) {
        ind = src[i];
        if (ind >= '0' && ind <= '9')
            seg = (seg * 10) + (ind - '0');
        else if (ind == '.') {
            dst[j++] = (unsigned char) seg;
            seg = 0;
        }
        else if (ind == '\0')
            break;
        else
            return -1;
    }
	dst[j] = (unsigned char) seg;

    return 0;
#endif
}

/**
 * @param	dst		Destination pointer where IPv6 binary form will be stored
 * @param	src		Source pointer in which string of IPv6 address is passed
 *					to this function
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		It converts IPv6 address in string form into binary form and stores it
 * in dst pointer. Like ip4_writer, it is also a wrapper over inet_pton
 */
int32_t ip6_writer(char *dst, const char *src) {

	/* NULL check */
	if (!dst || !src) {
		PGEN_INFO("NULL check failed\n");
		return -1;
	}

	if (inet_pton(AF_INET6, src, dst) == 0) {
		PGEN_INFO("Invalid IPv6 address");
		PGEN_PRINT_DATA("%s\n", src);
		return -1;
	}
	return 0;

	/* Could be helpful in future */
#if 0
	char temp[IPV6_ADDR_MAX_LEN] = {0}, c;
	unsigned int32_t seg = 0;
	int32_t i;

	if (!src || !dst)
		goto err;

	if (ip6_expander(temp, src))
		goto err;

	for (i = 0; i < strlen(temp); i++) {
		c = temp[i];

		if ((c >= '0') && (c <= '9'))
			seg = (seg*16) + (c-'0');
		else if ((c >= 'a') && (c <= 'f'))
			seg = (seg*16) + (c-'a') + 10;
		else if ((c >= 'A') && (c <= 'F'))
			seg = (seg*16) + (c-'A') + 10;
		else if (c == ':') {
			*dst++ = seg >> 8;
			*dst++ = seg & 255;
			seg = 0;
			continue;
		}
		else
			goto err;
	}
	*dst++ = seg >> 8;
	*dst++ = seg & 255;
	return 0;

err:
	return -1;
#endif
}

/**
 * @param	dst		Destination pointer where binary form of IPv6 prefix will
 *					be stored
 * @param	src		Source pointer in which string form of IPv6 address is
 *					supplied.
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		This function converts the IPv6 prefix from string form to binary form
 * and stores that in dst. As the prefix is not a valid IPv6 address, we could
 * not use inet_pton :(
 *
 * @Action_item
 *		This function could be made much wiser to allow user to give IPv6
 * address in short form
 */
int32_t ip6_prefix_writer(char *dst, char *value) {
	uint32_t i, one_char, two_char, pos = 1;
	char tmp[IPV6_ADDR_MAX_LEN] = {0};

	/* Fist expand the IPv6 prefix */
	if (ip6_expander(tmp, value))
		goto err;

	/* Convert character by character */
	for (i = 0; i < strlen(tmp); i++) {
		if ((tmp[i] >= 'a') && (tmp[i] <= 'f'))
			one_char = tmp[i] - 'a' + 10;
		else if ((tmp[i] >= 'A') && (tmp[i] <= 'F'))
			one_char = tmp[i] - 'A' + 10;
		else if ((tmp[i] >= '0') && (tmp[i] <= '9'))
			one_char = tmp[i] - '0';
		else if (tmp[i] == ':')
			continue;
		else
			goto err;

		if (pos == 1) {
			two_char = one_char;
			pos = 2;
		}
		else if (pos == 2) {
			two_char = two_char << 4;
			two_char = two_char | one_char;
			*dst = (uint8_t)two_char;
			dst++;
			pos = 1;
		}
	}

	return 0;

err:
	PGEN_INFO("Invalid IPv6 prefix");
	return -1;
}

/**
 * @param	dst		Destination pointer where expanded IPv6 address will be
 *					stored
 * @param	src		Source pointer in which IPv6 shorter form is passed
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 * 		This is used to expand the IPv6 address shorter form into its expanded
 * form.
 */
int32_t ip6_expander(char *dst, const char *src) {
	int32_t len, rem, dots;
	int32_t i, j = 0, k = 0;
	char intr[IPV6_ADDR_MAX_LEN], temp[5];

	if (!dst || !src)
		goto err;

	/* :: is the shortest IPv6 address - All zero IPv6 addr */
	if (!strcmp(src, "::")) {
		strcpy(dst, "0000:0000:0000:0000:0000:0000:0000:0000");
		return 0;
	}

	len = strlen(src);

	/* First expand all segments to four charcters each - [:89: --> :0089:] */
	for (i = 0; i < len; i++) {
		temp[j] = src[i];
		if (temp[j] == ':') {
			temp[j] = '\0';
			j = 0;

			rem = strlen(temp);

			if (!rem) {
				intr[k++] = ':';
				continue;
			}

			for (j = 0; j < (4-rem); j++)
				intr[k++] = '0';
			strcpy((intr+k), temp);
			k += rem;
			intr[k++] = ':';

			j = 0;
			continue;
		}
		j++;
	}
	temp[j] = '\0';
	rem = strlen(temp);
	if (!rem)
		goto err;
	for (j = 0; j < (4-rem); j++)
		intr[k++] = '0';
	strcpy((intr+k), temp);

	/* Fill the remaining zeros between :: */
	len = strlen(intr);
	for (i = 0, j = 0; i < len; i++) {
		dst[j] = intr[i];
		if (dst[j] == ':' && intr[i+1] == ':') {
			dots = IPV6_ADDR_MAX_LEN - len;
			for (k = 0; k < dots; k+=5 ) {
				if ((i != 0) || (k != 0))
					dst[j++] = ':';
				dst[j++] = '0';
				dst[j++] = '0';
				dst[j++] = '0';
				dst[j++] = '0';
			}
		}
		else
			j++;
	}
	return 0;

err:
	PGEN_INFO("Invalid IPv6 address/prefix");
	return -1;
}

int ip6_elide_prefix(char *op, char *value, int32_t len) {
	char ip6_addr[16];

	/* NULL Check */
	if (!value)
		goto err;

	if ((len > 16) || (len < 0))
		goto err;
	if (len == 16)
		return 0;

	if (inet_pton(AF_INET6, value, ip6_addr) < 1)
		goto err;

	memcpy(op, &ip6_addr[len], 16-len);
	return 0;

err:
	PGEN_INFO("Error while eliding prefix from IPv6 address");
	PGEN_PRINT_DATA("%s\n", value);
	return -1;
}

/**
 * @param	fp		file pointer to the configuration file
 * @param	option	The option will be stored in this pointer and passed back
 *					to the callee.
 * @param	value	The value for the option will be stored in this pointer and
 *					passed back to callee.
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 * 		To parse the configuration file. This function reads the line where
 * cursur is currently present and parses it. The option and its corresponding
 * value will be stored in option and value pointer respectively.
 */
int32_t pgen_parse_option(FILE *fp, char *option, char *value) {
	char line[MAX_LINE_LENGTH];
	char *c = NULL, *op, *val;
	char ch;

	if (!fp || !option || !value)
		goto err;

next:
	while (fscanf(fp, "%s", line) != EOF) {
        op = line;

		/* Ignore multiline comments */
		if (line[0] == '/' && line[1] == '*') {
			while (fscanf(fp, "%c", &ch) != EOF) {
				if (ch == '*') {
					if(fscanf(fp, "%c", &ch) != EOF) {
						if (ch == '/')
							goto next;
					}
					else
						goto err;
				}
			}
			goto err;
		}

        /* Ignore single line comments */
        if (line[0] == '#') {
            while (fscanf(fp, "%c", &ch) != EOF)
                if (ch == '\n')
                    break;
            continue;
        }

		/* In case 'Option=Value' combination */
        c = strchr(line, '=');
		if (c) {
            val = c + 1;
            *c = '\0';
            c = strchr(val, '\n');
            if (c)
                *c = '\0';
		    strcpy(value, val);
		}
		/* Else only 'Option'. f.e IPV6 */
		else {
			c = strchr(op, '\n');
			if (c)
				*c = '\0';
			strcpy(value, "");
		}

		strcpy(option, op);

		return 0; 
    }
	/* End of file is reached. This is an error case */
	return EOF;

err:
	PGEN_INFO("Parse Error");
	PGEN_PRINT_DATA("Line: %s\n", line);
	return 1;
}

/**
 * @param	num_orig	String that needs to be validated for number
 *
 * @return
 *			0			Success
 *			-1			Error
 *
 * @Description
 *		Validates whether the given string is number [hex/decimal]
 */
int validate_num(const char *num_orig) {
	int i;
	const char *num;

	/* Check for negative */
	if ((strlen(num_orig) > 1) && (num_orig[0] == '-'))
		num = &(num_orig[1]);
	else
		num = num_orig;

	/* if hex */
	if ((strlen(num) > 2) && (num[0] == '0') &&
		   ((num[1] == 'x') || (num[1] == 'X'))) {
		for (i = 2; i < strlen(num); i++) {
			if (((num[i] >= '0') && (num[i] <= '9')) ||
					((num[i] >= 'a') && (num[i] <= 'f')) ||
					((num[i] >= 'A') && (num[i] <= 'F')))
				continue;
			else
				goto err;
		}
	}

	/* Or consider as decimal */
	else {
		for (i = 0; i < strlen(num); i++) {
			if ((num[i] >= '0') && (num[i] <= '9'))
				continue;
			else
				goto err;
		}
		if (i == 0)
			goto err;
	}
	return 0;

err:
	PGEN_INFO("Number validation failed");
	PGEN_PRINT_DATA("%s\n", num);
	return -1;
}

/**
 * @param	i		Destination pointer where converted decimal value will
 *					be stored.
 * @param	c		Source pointer in which string form of the the number
 *					is passed by
 *
 * @return
 *			0		Success
 *			-ERRNO	Error
 *
 * @Description
 * 		Converts character numbers into their decimal values.
 * As it depends on strtol, this function doesn't bother about
 * rear non-number characters. It is just a wrapper over strtol
 */
int32_t pgen_store_num(int32_t *i, const char *c) {

	/* Arg. NULL check */
	if (!i || !c) {
		PGEN_INFO("Argument NULL check failed");
		return -1;
	}

	if (validate_num(c))
		return -1;

	/* if given in hex */
	if ((strlen(c) > 2) && (c[0] == '0') && ((c[1] == 'x') || c[1] == 'X')) {
		errno = 0;
		*i = strtol(c, NULL, 16);
		if (errno) {
			PGEN_INFO("Conversion from hex failed");
			return -errno;
		}
	}
	/* Or consider as decimal */
	else {
		errno = 0;
		*i = strtol(c, NULL, 10);
		if (errno) {
			PGEN_INFO("Conversion from decimal failed");
			return -errno;
		}
	}

	return 0;
}

/**
 * @param	if_name		Name of the network interface which should be verified
 *
 * @return
 *			0			Success
 *			-1			Error
 *
 * @Description
 *			Verifies whether the passed network interface is a legitimate one.
 * It just checks whether the interface is available and UP.
 */
int32_t validate_if(const char *if_name) {
    struct ifreq req;
    int32_t sockfd;

	/* Null check */
	if (!if_name) {
		PGEN_INFO("Argument is NULL");
		goto err;
	}

	/* To get interface's index and flags, we need a socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
		PGEN_ERROR("Socket creation failed", errno);
		goto err;
    }

    memset(&req, 0, sizeof(struct ifreq));
    strcpy(req.ifr_name, if_name);

	/**
	 * Get Interface index for the given interface name.
	 * If index is available, it confirms that the interface
	 * is a valid one.
	 */
    if (ioctl(sockfd, SIOCGIFINDEX, &req) < 0) {
		PGEN_ERROR("ioctl - Get index", errno);
        goto err;
    }

	/* Get flags related to the interface */
    if (ioctl(sockfd, SIOCGIFFLAGS, &req) < 0) {
		PGEN_ERROR("ioctl - Get flags", errno);
        goto err;
    }

	/**
	 * Check whether the interface is UP.
	 * This doesn't check whether the interface is connected or not.
	 */
    if (!(req.ifr_flags & IFF_UP)) {
		PGEN_INFO("Interface is down");
        goto err;
    }

    close(sockfd);
    return 0;
err:
    close(sockfd);
    return -1;
}

/**
 * @param	op		place holder where the option will be writter
 * @param	name	The name which will be encoded and added to option
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Encodes the given name as described in RFC-1035 Sec-3.1
 */
int encode_name(char *buff, const char *name) {
	int len = 0, i;

	/* NULL check */
	if (!buff || !name)
		goto err;

	len = strlen(name);
	if (len == 0)
		goto err;
	/* len byte */
	else {
		*buff = len;
		buff++;
	}

	for (i = 0; i < len; i++) {
		*buff = name[i];
		buff++;
	}

	/* terminate byte */
	buff++;

	return (len + 2);

err:
	PGEN_INFO("Error while encoding name");
	PGEN_PRINT_DATA("%s\n", name);
	return -1;

}

/**
 * @param	buff	option place holder where the option will be written
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes PAD1 option in given place.
 */
int pad1(char* buff) {

	/* NULL check */
	if (!buff)
		return -1;

	return 0;
}

/**
 * @param	fp		file pointer to the configuration file
 * @param	buff	place holder where the option will be written
 *
 * @return
 *			0		Success
 *			-1		Error
 *
 * @Description
 *		Writes padN option at op.
 */
int padN(FILE *fp, char *buff) {
	char option[MAX_OPTION_LEN], value[MAX_VALUE_LEN];
	/* the N in pad'N' */
	int32_t n;

	/* NULL check */
	if (!buff)
		goto err;

	if (pgen_parse_option(fp, option, value))
		goto err;

	if (strcmp(option, "PADN_N"))
		goto err;

	if (pgen_store_num(&n, value))
		goto err;

	/* option len is an 1-Byte entity */
	if ((n < 2) || (n > 255))
		goto err;
	n = n - 2;

	/* initial 'one' byte */
	*buff = (uint8_t)1;
	buff++;

	/* len */
	*buff = (uint8_t)n;
	buff++;

	/* pad with zeros */

	return n + 2;

err:
	PGEN_INFO("Error while writing PadN option");
	PGEN_PRINT_DATA("%s\t%s\n", option, value);
	return -1;
}

/**
 * @param	fp		File pointer to the configuration file
 * @param	buff	buffer where the data will be written
 *
 * @return
 *			len		Success
 *			-1		Error
 *
 * @Description
 *		Dumps hex string into buff.
 */
int raw_data_writer(FILE *fp, char *buff) {
	char option[MAX_OPTION_LEN], value[MAX_RAW_DATA_LEN], val;
	uint8_t byte = 0;
    uint32_t i;

    /* NULL check */
    if (!buff)
        goto err;

	if (pgen_parse_option(fp, option, value))
		goto err;
	if (strcmp(option, "RAW_DATA"))
		goto err;

    /* expects user to use 0x/0X prefix for the hex option value */
    if ((value[0] != '0') && (value[1] != 'x' || value[1] != 'X'))
        goto err;

    /* Read a nibble at a time and write a byte */
	i = 2;
    while (value[i] != '\0') {
		val = value[i];
        if (val >= '0' && val <= '9')
            byte = byte * 16 + val - '0';
        else if (val >= 'a' && val <= 'f')
            byte = byte * 16 + val - 'a' + 10;
        else if (val >= 'A' && val <= 'F')
            byte = byte * 16 + val - 'A' + 10;
        else
            goto err;

        if (i % 2 != 0) {
            *buff++ = byte;
            byte = 0;
        }
		i++;
    }
    
	/* length of the hex value must be in even */
    if (i % 2 != 0)
        goto err;
    else
        /* Return length of option */
        return (i/2 - 1);

err:
	PGEN_INFO("Error while writing RAW data");
	PGEN_PRINT_DATA("%s\t%s\n", option, value);
    return -1;
}
