#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "tcpip.h"

int main(void) {

	int tun = openTun("tun0");

	// Sending a SYN packet

	struct tcp * syn = calloc(1, sizeof(*syn));
	TCP(20000, 80, 0, 0, TCP_SYN, OPT_MSS, syn);

	struct ipv4 * ip = calloc(1, sizeof(*ip));
	IPV4(sizeof(*syn), PROTO_TCP, "93.184.216.34", ip);

	size_t size = sizeof(*ip) + sizeof(*syn);

	char packet[size];
	make_tcp_packet(ip, syn, packet);
	
	char buffer[1024] = {0};

	write(tun, packet, size);
	read(tun, buffer, sizeof(buffer));

	struct tcp * synack = calloc(1, sizeof(*synack));
	memcpy(synack, buffer + sizeof(*ip), sizeof(*synack));

	free(syn);

	memset(packet, 0, sizeof(packet));
	memset(buffer, 0, sizeof(buffer));

	// Sending an ACK packet

	struct tcp * ack = calloc(1, sizeof(*ack));
	TCP(20000, 80, ntohl(synack->ack), ntohl(synack->seq)+1, TCP_ACK, 0, ack);

	ip->len = htons(20 + sizeof(*ack));
	ip->checksum = 0;
	ip->checksum = checksum(ip, sizeof(*ip));

	size = sizeof(*ip) + sizeof(*ack);
	make_tcp_packet(ip, ack, packet);

	print_bytes(packet, size);

	write(tun, packet, size);

	free(ack);

	// Sending a RST packet

	struct tcp * rst = calloc(1, sizeof(*rst));
	TCP(20000, 80, ntohl(synack->ack), 0, TCP_RST, 0, rst);

	ip->len = htons(20 + sizeof(*rst));
	ip->checksum = 0;
	ip->checksum = checksum(ip, sizeof(*ip));

	size = sizeof(*ip) + sizeof(*rst);
	make_tcp_packet(ip, rst, packet);

	write(tun, packet, size);

	free(rst);

	free(ip);
	close(tun);

	return 0;
}
