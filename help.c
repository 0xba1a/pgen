#include "pgen.h"

void usage() {
	printf("Usage : pgen [conf_file]\n");
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
        else {
			printf("erro: %c\n", ind);
            return -1;
		}
    }
	dst[j] = (unsigned char) seg;
    return 0;
}

int ip4_writer(char *dst, const char *src) {
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
}

