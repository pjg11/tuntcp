#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include "tcpip.h"

#define IFNAMSIZ 16

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
	inet_pton(AF_INET, "192.0.2.2", &(ip->src));
	inet_pton(AF_INET, daddr, &(ip->dst));

	ip->checksum = checksum(ip, sizeof(*ip));

	return ip;
}

struct icmpecho * ICMPEcho(uint16_t seq) {

	struct icmpecho * echo = calloc(1, sizeof(struct icmpecho));

	echo->type = 8;
	echo->code = 0;
	echo->checksum = 0;
	echo->id = htons(12345);
	echo->seq = htons(seq);

	echo->checksum = checksum(echo, sizeof(*echo));
	return echo;

}

struct tcp * TCP(uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags, uint32_t options) {

	struct tcp * t = calloc(1, sizeof(struct tcp));

	t->sport = htons(sport);
	t->dport = htons(dport);
	t->seq = htonl(seq);
	t->ack = htonl(ack);
	t->rsvd_offset = 6 << 4;

	t->flags = flags;
	t->win = htons(65535);
	t->checksum = 0;
	t->urp = 0;

	t->options = htonl(options);

	return t;
}

void * make_tcp_packet(struct ipv4 * i, struct tcp * t, char* p) {

	struct pseudoheader * ph = calloc(1, sizeof(struct pseudoheader));
	ph->src = i->src;
	ph-> dst = i->dst;
	ph->proto = i->proto;
	ph->tcp_len = htons(ntohs(i->len) - 20); // confused about this
	
	size_t size = sizeof(*ph) + sizeof(*t);

	char sum_data[size];
	memset(sum_data, 0, size);
	
	to_bytes(ph, sum_data, sizeof(*ph));
	to_bytes(t, sum_data + sizeof(*ph), sizeof(*t));

	t->checksum = checksum(sum_data, size);

	free(ph);

	to_bytes(i, p, sizeof(*i));
	to_bytes(t, p + sizeof(*i), sizeof(*t));
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

void to_bytes(void *data, char *dst, size_t len) {
	memcpy(dst, (char *) data, len);
}

int openTun(char *dev) {
	struct ifreq ifr;
	int fd, err;

	if( (fd = open("/dev/net/tun", O_RDWR)) < 0 )
		return 1;

	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if( (err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0 ){
		close(fd);
		return err;
	}

	char addr[INET_ADDRSTRLEN];

	return fd;
}

