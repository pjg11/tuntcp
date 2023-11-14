#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <time.h>
#include <ctype.h>
#include "tuntcp.h"

int main(void) {

	int tun = openTun("tun0");
	struct tcp_conn conn;
	TCPConnection(tun, "93.184.216.34", 80, &conn);
	char buffer[1024] = {0};

	// Sending a SYN packet
	send_tcp_packet(&conn, TCP_SYN);
	conn.state = TCP_SYN_SENT;

	read(tun, buffer, sizeof(buffer));

	struct ipv4 *ip = buf2ip(buffer);
	struct tcp *tcp = buf2tcp(buffer, ip);
	int tcplen = ipdlen(ip);

	conn.seq = ntohl(tcp->ack);
	conn.ack = ntohl(tcp->seq) + 1;

	// Sending an ACK packet
	send_tcp_packet(&conn, TCP_ACK);
	conn.state = TCP_ESTABLISHED;

	// Sending a RST packet
	send_tcp_packet(&conn, TCP_RST);
	
	conn.state = TCP_CLOSED;
	return 0;
}
