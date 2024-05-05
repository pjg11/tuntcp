#include "tuntcp.h"

int main(void) {
  int tun, len;
  tcpconn c;
  packet r;
  packet *recv = &r;
  char data[] =
      "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";

  tun = openTun("tun0");
  conn("208.94.117.43", 80, tun, &c);

  tcpsend(&c, TCP_SYN, "", 0);

  tcphdr synack = tcprecv(&c);
  c.seq = ntohl(synack.ack);
  c.ack = ntohl(synack.seq) + 1;

  tcpsend(&c, TCP_ACK, "", 0);
  c.state = ESTABLISHED;

  tcpsend(&c, TCP_PSH | TCP_ACK, data, sizeof(data) - 1);
  c.seq += sizeof(data) - 1;

  while ((len = timeoutread(tun, recv, 540)) > 0) {
    hexdump((char *)&recv->tcp + 40, len);
  }

  tcpsend(&c, TCP_RST, "", 0);
  close(tun);
  return 0;
}
