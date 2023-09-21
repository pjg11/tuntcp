#include <stdlib.h>
#include <string.h>
#include "tcpip.h"

int main(void) {
	struct icmpecho * echo = ICMPEcho(1);
	struct ipv4 * ip = IPV4(sizeof(*echo), PROTO_TCP, "208.94.117.43");

	size_t size = sizeof(*ip) + sizeof(*echo);
	char *packet = calloc(1, size);

	memcpy(packet, ip, sizeof(*ip));
	memcpy(packet + sizeof(*ip), echo, sizeof(*echo));

	print_bytes(packet, size);

	free(echo);
	free(ip);
	return 0;
}