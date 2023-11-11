#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>
#include "tuntcp.h"

int main(void) {

	srand(time(NULL));

	int tun = openTun("tun0");
	char buffer[1024] = {0};
	char *dest = "93.184.216.34";
	uint32_t iss = rand();
	uint16_t sport = rand() % INT16_MAX;

	// Sending a SYN packet
	send_tcp_packet(dest, tun, TCP_SYN, iss, 0, sport, 80);
	read(tun, buffer, sizeof(buffer));

	struct tcp * synack = calloc(1, sizeof(*synack));
	struct ipv4 * synackip = calloc(1, sizeof(*synackip));
	memcpy(synackip, buffer, sizeof(*synackip));
	memcpy(synack, buffer + sizeof(*synackip), sizeof(*synack));

	memset(buffer, 0, sizeof(buffer));

	// Sending an ACK packet
	send_tcp_packet(dest, tun, TCP_ACK, ntohl(synack->ack), ntohl(synack->seq)+1, sport, 80);

	// Sending a RST packet
	send_tcp_packet(dest, tun, TCP_ACK, ntohl(synack->ack), 0, sport, 80);

	free(synack);
	free(synackip);

	return 0;
}
