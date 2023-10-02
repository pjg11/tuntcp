#define _POSIX_C_SOURCE 199309L
#define IFNAMSIZ 16

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <time.h>
#include "tcpip.h"

int main(int argc, char *argv[]) {

	if (argc < 3) {
		printf("Usage: ./ping num ip");
		return 1;
	}

	int tun = openTun("tun0");

	char addr[INET_ADDRSTRLEN];

	size_t size = sizeof(struct ipv4) + sizeof(struct icmpecho);
	char *packet = malloc(size);

	struct ipv4 *ip = IPV4(sizeof(struct icmpecho), 1, argv[2]);

	printf("PING %s %d bytes of data.\n", inet_ntop(AF_INET, &(ip->dst), addr, INET_ADDRSTRLEN), ntohs(ip->len));
	
	struct timeval tv;
    tv.tv_sec  = 500 / 1000;
    tv.tv_usec = (500 % 1000) * 1000;
    select(0, NULL, NULL, NULL, &tv);
	
	for (int i = 0; i < atoi(argv[1]); i++) {
		
		struct icmpecho *echo = ICMPEcho(i+1);
		to_bytes(ip, packet, sizeof(*ip));
		to_bytes(echo, packet + sizeof(*ip), sizeof(*echo));
		
		char response[size];

		struct timespec start, end;

		clock_gettime(CLOCK_REALTIME, &start);
		
		write(tun, packet, size);
		int len = read(tun, response, sizeof(response));

		clock_gettime(CLOCK_REALTIME, &end);

		struct icmpecho *echoreply = calloc(1, sizeof(struct icmpecho));
		struct ipv4 *ipreply = calloc(1, sizeof(struct ipv4));
		
		memcpy(ipreply, response, sizeof(*ipreply));
		memcpy(echoreply, (void *)response + sizeof(*ipreply), sizeof(*echoreply));

    	double elapsed = (end.tv_sec - start.tv_sec) + ((end.tv_nsec - start.tv_nsec) / 1000000.0);
		printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n", len, "8.8.8.8", ntohs(echoreply->seq), ipreply->ttl, elapsed);
	
		sleep(1);
	}

	free(ip);
	free(packet);
	close(tun);
	return 0;
}