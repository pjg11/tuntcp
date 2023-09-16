#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>

// https://www.rfc-editor.org/rfc/rfc791
// http://lxr.linux.no/linux+v2.6.38/include/linux/ip.h
// https://beej.us/guide/bgnet/html/#byte-order
// https://beej.us/guide/bgnet/html/#inet_ntopman
// https://www.rfc-editor.org/rfc/rfc1071

struct ipv4 {
	uint8_t 	version_ihl;
	uint8_t		tos;
	uint16_t	len;
	uint16_t	id;
	uint16_t	frag_offset;
	uint8_t		ttl;
	uint8_t		proto;
	uint16_t	checksum;
	uint32_t	src;
	uint32_t	dst;
};

void print_bytes(char *bytes, size_t len) {
	for(size_t i = 0; i < len; i++) {
		printf("%c", bytes[i]);
	}
}

void bytes(void *data, char *dst, size_t len) {
	memcpy(dst, (char *) data, len);
}

uint16_t checksum(void *data, size_t count) {
	register uint32_t sum = 0;
	uint16_t *p = data;

	while( count > 1 )  {
		sum += *p++;
		count -= 2;
	}

	if( count > 0 )
		sum += * (uint8_t *) data;

	while (sum>>16)
		sum = (sum & 0xffff) + (sum >> 16);

	return ~sum;
}

int main(void) {
	struct ipv4 * ip = calloc(1, sizeof(struct ipv4));
	uint32_t saddr, daddr;
	inet_pton(AF_INET, "10.0.2.15", &saddr);
	inet_pton(AF_INET, "34.194.149.67", &daddr);

	ip->version_ihl = 69;
	ip->tos = 0;
	ip->len = ntohs(44);
	ip->id = ntohs(1);
	ip->frag_offset = ntohs(0);
	ip->ttl = 63;
	ip->proto = 6;
	ip->checksum = ntohs(0);
	ip->src = saddr;
	ip->dst = daddr;

	ip->checksum = checksum(ip, sizeof(*ip));

	char b[sizeof(*ip)];
	bytes(ip, b, sizeof(*ip));
	print_bytes(b, sizeof(*ip));
	
	free(ip);
	return 0;
}