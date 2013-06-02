#ifndef PGEN_H
#define PGEN_H 1

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <errno.h>
#include <linux/limits.h>

#define DEF_PGEN_CONF "/etc/pgen.conf"
#define ETH_ALEN 6
#define IPV6_ADDR_MAX_LEN 40
#define CHAR_MAC_LEN 18
#define MAX_OPTION_LEN 200
#define MAX_VALUE_LEN 200
#define MAX_LINE_LENGTH 1024

#define PGEN_INFO(MSG) do {                                                    \
	fprintf(stdout, "File:%s, Line:%d, %s\n", __FILE__,	__LINE__, MSG);        \
	} while(0)
#define PGEN_ERROR(MSG, errno) do {                                            \
	fprintf(stderr, "File:%s, Line:%d, %s, errno:%d\n", __FILE__, __LINE__,    \
			MSG, errno);                                                       \
	} while(0)
#define PGEN_PRINT_DATA(...) do {                                              \
	fprintf(stdout, __VA_ARGS__);                                              \
	} while (0)

char* pgen_ethr_hdr_writer(FILE *, char *);
char* pgen_arp_writer(FILE *, char *);
char* pgen_ipv6_writer(FILE *, char *);

/* Helpers */
void usage();
int pgen_strcmp(const char *, const char *);
int pgen_parse_option(FILE *, char *, char *);
int send_packet(const char *, const char *, const char *, const int);
int mac_writer(char *, const char *);
int ip4_writer(char *, const char *);
int pgen_store_dec(int *, const char *);
#endif /* PGEN_H */
