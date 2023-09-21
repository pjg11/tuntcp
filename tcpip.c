#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "tcpip.h"

struct ipv4 * IPV4(size_t len_contents, uint8_t protocol, char *daddr) {
	
	struct ipv4 * ip = calloc(1, sizeof(struct ipv4));

	ip->version_ihl = 4 << 4 | 5;
	ip->tos = 0;
	ip->len = htons(20 + len_contents);
	ip->id = htons(1);
	ip->frag_offset = 0;
	ip->ttl = 64;
	ip->proto = protocol;
	ip->checksum = 0;
	inet_pton(AF_INET, "10.0.2.15", &(ip->src));
	inet_pton(AF_INET, daddr, &(ip->dst));

	ip->checksum = htons(checksum(ip, sizeof(*ip)));

	return ip;
}

struct icmpecho * ICMPEcho(uint16_t seq) {

	struct icmpecho * echo = calloc(1, sizeof(struct icmpecho));

	echo->type = 8;
	echo->code = 0;
	echo->checksum = 0;
	echo->id = htons(12345);
	echo->seq = htons(seq);

	echo->checksum = htons(checksum(echo, sizeof(*echo)));
	return echo;

}

uint16_t checksum(void *data, size_t count) {

	register uint32_t sum = 0;
	uint16_t *p = data;

	while (count > 1)  {
		sum += *p++;
		count -= 2;
	}

	if (count > 0)
		sum += * (uint8_t *) data;

	while (sum >> 16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

void print_bytes(void *bytes, size_t len) {
    char *b = (char *) bytes;
	for (size_t i = 0; i < len; i++) {
		printf("%c", b[i]);
	}
}

void bytes(void *data, char *dst, size_t len) {
	memcpy(dst, (char *) data, len);
}