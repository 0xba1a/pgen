#include "pgen.h"

void usage() {
	printf("Usage : pgen [conf_file]\n");
}

int pgen_strcmp(const char *s1, const char *s2) {
	return strncmp(s1, s2, strlen(s2) + 1);
}

int send_packet(const char *if_name, const char *dst_mac, const char *cp_buff,
		const int buff_size) {
	int sockfd;
	struct sockaddr_ll s_sock_addr;
	struct ifreq s_if_idx;
	struct ifreq s_if_mac;

	/* Get the RAW socket */
    sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket");
        goto err;
    }

	/* Get the index of the interface */
    memset(&s_if_idx, 0, sizeof (struct ifreq));
    strcpy(s_if_idx.ifr_name, if_name);
    if (ioctl(sockfd, SIOCGIFINDEX, &s_if_idx) < 0) {
        perror("ioctl, index");
        goto err;
    }

    /* Get the MAC address of the interface */
    memset(&s_if_mac, 0, sizeof(struct ifreq));
    strcpy(s_if_mac.ifr_name, if_name);
    if (ioctl(sockfd, SIOCGIFHWADDR, &s_if_mac) < 0) {
        perror("ioctl, hwaddr");
        goto err;
    }

    /* Set sending socket address */
    s_sock_addr.sll_ifindex = s_if_idx.ifr_ifindex;
    s_sock_addr.sll_halen = ETH_ALEN;
    if (mac_writer(s_sock_addr.sll_addr, dst_mac)) {
        fprintf(stderr, "SOCK: dst mac writing error\n");
        goto err;
    }

	if (sendto(sockfd, cp_buff, buff_size, 0,
                (struct sockaddr *)&s_sock_addr,
                sizeof(struct sockaddr_ll)) < 0) {
        perror("sendto");
        goto err;
    }
	return 0;
err:
	return -1;
}

int mac_writer(char *dst, const char *src) {
    int seg = 0;
    char ind;
    int i, j = 0;

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
            return -1;
    }
	dst[j] = (unsigned char) seg;
    return 0;
}

int ip4_writer(char *dst, const char *src) {

	struct in_addr *sin_addr = (struct in_addr *)dst;
	if (inet_pton(AF_INET, src, sin_addr) == 0) {
		fprintf(stderr, "invalid IP address\n");
		return -1;
	}
	return 0;

	/* Could be helpful later */
#if 0
    int seg = 0;
    char ind;
    int i, j = 0;
    
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

int ip6_writer(char *dst, const char *src) {
	struct in6_addr *sin6_addr = (struct in6_addr *)dst;
	if (inet_pton(AF_INET6, src, sin6_addr) == 0) {
		fprintf(stderr, "Invalid IPv6 address\n");
		return -1;
	}
	return 0;

	/* Could be helpful in future */
#if 0
	char temp[IPV6_ADDR_MAX_LEN] = {0}, c;
	unsigned int seg = 0;
	int i;

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

int ip6_expander(char *dst, const char *src) {
	int len, rem, dots;
	int i, j = 0, k = 0, nxt_col;
	char intr[IPV6_ADDR_MAX_LEN], temp[5];

	if (!dst || !src)
		goto err;

	if (!strcmp(src, "::")) {
		strcpy(dst, "0000:0000:0000:0000:0000:0000:0000:0000");
		return 0;
	}

	len = strlen(src);

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
	return -1;
}

int pgen_parse_option(FILE *fp, char *option, char *value) {
	char line[MAX_LINE_LENGTH];
	char *c = NULL, *op, *val;
	char ch;

next:
	while (fscanf(fp, "%s", line) != EOF) {
        op = line;

		/* Ignore multiple line comments */
		if (line[0] == '/' && line[1] == '*') {
			while (fscanf(fp, "%c", &ch) != EOF)
				if (ch == '*')
					if(fscanf(fp, "%c", &ch) != EOF) {
						if (ch == '/')
							goto next;
					}
					else
						goto err;
			goto err;

		}

        /* Ignore single line comments */
        if (line[0] == '#') {
            while (fscanf(fp, "%c", &ch) != EOF)
                if (ch == '\n')
                    break;
            continue;
        }

        c = strchr(line, '=');
        if (!c) {
            perror("Syntax error in conf file\n");
            goto err;
        }

        val = c + 1;
        *c = '\0';
        c = strchr(value, '\n');
        if (c)
            *c = '\0';

		strcpy(option, op);
		strcpy(value, val);

       return 0; 
    }
	return EOF;

err:
	printf("parse: %s\n", line);
	return 1;

}

int pgen_store_dec(int *i, const char *c) {
	errno = 0;
	*i = strtol(c, NULL, 10);
	if (errno)
		return -1;

	return 0;
}

int pgen_strcpy(char *dst, const char *src) {
	if (strncpy(dst, src, strlen(src)+1))
		return 0;
	perror("strncpy");
	return -1;
}
