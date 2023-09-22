#ifndef TCPIP_H
#define TCPIP_H

#include <stdint.h>
#include <stdlib.h>

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

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

struct icmpecho {
   uint8_t 	type;
   uint8_t 	code;
   uint16_t checksum;
   uint16_t id;
   uint16_t seq;
};

struct ipv4 * IPV4(size_t len_contents, uint8_t protocol, char *daddr);
struct icmpecho * ICMPEcho(uint16_t seq);

uint16_t checksum(void *data, size_t count);
void print_bytes(void *bytes, size_t len);
void bytes(void *data, char *dst, size_t len);
int openTun(char *dev);

#endif