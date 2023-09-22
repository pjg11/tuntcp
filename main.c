#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tcpip.h"

int main(void) {

	int tun = openTun("tun0");

	struct icmpecho * echo = ICMPEcho(1);
	struct ipv4 * ip = IPV4(sizeof(*echo), PROTO_ICMP, "8.8.8.8");

	size_t size = sizeof(*ip) + sizeof(*echo);
	
	char *packet = calloc(1, size);

	memcpy(packet, ip, sizeof(*ip));
	memcpy(packet + sizeof(*ip), echo, sizeof(*echo));

	char buffer[1024];
	memset(buffer, 0, sizeof(buffer));

	write(tun, packet, size);
	int len = read(tun, buffer, sizeof(buffer));

	print_bytes(buffer, sizeof(buffer));

	free(packet);
	free(ip);
	free(echo);

	close(tun);
	return 0;
}