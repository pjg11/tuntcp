#include <stdlib.h>
#include "tcpip.h"

int main(void) {
	struct ipv4 * ip = IPV4("", PROTO_TCP, "208.94.117.43");
	print_bytes(ip, sizeof(*ip));
	
	free(ip);
	return 0;
}