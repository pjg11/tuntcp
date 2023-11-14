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
#include "tuntcp.h"
#include <time.h>
#include <ctype.h>

#define IFNAMSIZ 16

void IPV4(size_t len_contents, uint8_t protocol, char *daddr, struct ipv4 * ip) {
	
	ip->version_ihl = 4 << 4 | 5;
	ip->tos = 0;
	ip->len = htons(sizeof(*ip) + len_contents);
	ip->id = htons(1);
	ip->frag_offset = 0;
	ip->ttl = 64;
	ip->proto = protocol;
	ip->checksum = 0;
	inet_pton(AF_INET, "192.0.2.2", &(ip->src));
	inet_pton(AF_INET, daddr, &(ip->dst));

	ip->checksum = checksum(ip, sizeof(*ip));
}

void ICMPEcho(uint16_t seq, struct icmpecho * echo) {

	echo->type = 8;
	echo->code = 0;
	echo->checksum = 0;
	echo->id = htons(12345);
	echo->seq = htons(seq);

	echo->checksum = checksum(echo, sizeof(*echo));

}

void TCP(uint16_t sport, uint16_t dport, uint32_t seq, uint32_t ack, uint8_t flags, struct tcp * tcp) {

	tcp->sport = htons(sport);
	tcp->dport = htons(dport);
	tcp->seq = htonl(seq);
	tcp->ack = htonl(ack);
	tcp->rsvd_offset = (sizeof(*tcp) >> 2) << 4;
	tcp->flags = flags;
	tcp->win = htons(65535);
	tcp->checksum = 0;
	tcp->urp = 0;
}

void TCPConnection(int tun, char *addr, uint16_t port, struct tcp_conn *conn) {
	
	srand(time(NULL));

	conn->tun = tun;
	conn->state = TCP_CLOSED;

	inet_pton(AF_INET, "192.0.2.2", &(conn->src_addr));
	conn->src_port = rand() % INT16_MAX;

	conn->dst_addr = addr;
	conn->dst_port = port;

	conn->seq = rand();
	conn->ack = 0;
}

void send_tcp_packet(struct tcp_conn *conn, uint8_t flags) {

	struct tcp tcp;
	TCP(conn->src_port, conn->dst_port, conn->seq, conn->ack, flags, &tcp);

	struct ipv4 ip;
	IPV4(sizeof(tcp), PROTO_TCP, conn->dst_addr, &ip);

	tcp.checksum = tcp_checksum(&ip,&tcp);

	size_t size = sizeof(ip) + sizeof(tcp);
	char packet[size];
	memcpy(packet, &ip, sizeof(ip));
	memcpy(packet + sizeof(ip), &tcp, sizeof(tcp));
	
	write(conn->tun, packet, size);
}

uint16_t tcp_checksum(struct ipv4 *ip, struct tcp *tcp) {
	struct pseudoheader * ph = calloc(1, sizeof(struct pseudoheader));
	ph->src = ip->src;
	ph-> dst = ip->dst;
	ph->proto = ip->proto;
	ph->tcp_len = htons(ntohs(ip->len) - sizeof(*ip));
	size_t size = sizeof(*ph) + sizeof(*tcp);

	char sum_data[size];
	memset(sum_data, 0, size);
	
	to_bytes(ph, sum_data, sizeof(*ph));
	to_bytes(tcp, sum_data + sizeof(*ph), sizeof(*tcp));

	free(ph);
	
	return checksum(sum_data, size);
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

	return fd;
}

