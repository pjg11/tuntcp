#ifndef TCPIP_H
#define TCPIP_H

#include <stdint.h>
#include <stdlib.h>

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

#define TCP_FIN 1
#define TCP_SYN 2
#define TCP_RST 4
#define TCP_PSH 8
#define TCP_ACK 16
#define TCP_URG 32
#define TCP_ECE 64
#define TCP_CWR 128

#define OPT_EOL 0
#define OPT_NOP 1
#define OPT_MSS (2 << 8 | 4) << 16 | 1460

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
	uint16_t	checksum;
	uint16_t	id;
	uint16_t	seq;
};

struct tcp {
	uint16_t	sport;
	uint16_t	dport;
	uint32_t	seq;
	uint32_t	ack;
	uint8_t		rsvd_offset;
	uint8_t		flags;
	uint16_t	win;
	uint16_t	checksum;
	uint16_t	urp;
	uint32_t	options;
};

struct pseudoheader {
	uint32_t	src;
	uint32_t	dst;
	uint8_t		zero;
	uint8_t		proto;
	uint16_t	tcp_len;
};

void IPV4(size_t len_contents, uint8_t protocol, char *daddr, struct ipv4 * ip);
void ICMPEcho(uint16_t seq, struct icmpecho * echo);
void TCP(uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags, uint32_t options, struct tcp * tcp);
void make_tcp_packet(struct ipv4 * i, struct tcp * t, char *p);

uint16_t checksum(void *data, size_t count);
void print_bytes(void *bytes, size_t len);
void to_bytes(void *data, char *dst, size_t len);
int openTun(char *dev);

#endif
