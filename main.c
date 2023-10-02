#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include "tcpip.h"

int main(void) {

	int tun = openTun("tun0");

	// Sending a SYN packet

	struct tcp * syn = TCP(30000, 80, 0, 0, TCP_SYN, OPT_MSS);
	struct ipv4 * ip = IPV4(sizeof(*syn), PROTO_TCP, "93.184.216.34");

	size_t size = sizeof(*ip) + sizeof(*syn);

	char packet[size];
	make_tcp_packet(ip, syn, packet);
	
	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	write(tun, packet, size);
	int len = read(tun, buffer, sizeof(buffer));

	struct tcp * synack = calloc(1, sizeof(*synack));
	memcpy(synack, buffer + sizeof(*ip), sizeof(*synack));

	free(syn);
	free(ip);

	memset(packet, 0, sizeof(packet));
	memset(buffer, 0, sizeof(buffer));

	// Sending an ACK packet
	printf("%x %x\n", ntohl(synack->seq), ntohl(synack->seq)+1);

	struct tcp * ack = TCP(30000, 80, ntohl(synack->ack), ntohl(synack->seq)+1, TCP_ACK, 0);
	struct ipv4 * ip2 = IPV4(sizeof(*ack), PROTO_TCP, "93.184.216.34");

	size = sizeof(*ip2) + sizeof(*ack);
	make_tcp_packet(ip2, ack, packet);

	write(tun, packet, size);

	free(ip2);
	free(ack);

	// Sending a RST packet

	struct tcp * rst = TCP(30000, 80, ntohl(synack->ack), 0, TCP_RST, 0);
	struct ipv4 * ip3 = IPV4(sizeof(*rst), PROTO_TCP, "93.184.216.34");

	size = sizeof(*ip3) + sizeof(*rst);
	make_tcp_packet(ip3, rst, packet);

	write(tun, packet, size);

	free(ip3);
	free(rst);

	close(tun);
	return 0;
}
