#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <asm/byteorder.h>
#include <string.h>

// https://www.rfc-editor.org/rfc/rfc791
// http://lxr.linux.no/linux+v2.6.38/include/linux/ip.h
// https://www.geeksforgeeks.org/bit-fields-c/
// https://beej.us/guide/bgnet/html/#byte-order

#define PROTO_ICMP 1
#define PROTO_TCP 6

struct IPHeader {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t    ihl : 4,
				version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	uint8_t    version : 4,
				ihl : 4;
#endif
	uint8_t 	tos;
	uint16_t 	len;
	uint16_t 	id;
	uint16_t	frag_offset;
	uint8_t		ttl;
	uint8_t		proto;
	uint16_t	checksum;
	uint32_t	src;
	uint32_t	dst;
};

int main(void) {
	struct IPHeader *ip = calloc(1, sizeof(struct IPHeader));
	uint32_t saddr;
	inet_pton(AF_INET, "10.0.2.15", &(saddr));
	
	uint32_t daddr;
	inet_pton(AF_INET, "34.194.149.67", &(daddr));

	ip->version = 4;
	ip->ihl = 5;
	ip->tos = 0;
	ip->len = 20;
	ip->id = 1;
	ip->frag_offset = 0;
	ip->ttl = 16;
	ip->proto = 6;
	ip->checksum = 0;
	ip->src = saddr;
	ip->dst = daddr;

	unsigned char *p = (unsigned char *) ip;
	size_t size = sizeof(*ip);
    while (size--) {
		printf("%.2x ", (*p++));
    }

	free(ip);
}