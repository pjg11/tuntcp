#include "tuntcp.h"

int main(void) {
  int tun;
  tcpconn c;
  packet r;
  packet *recv = &r;
  char data[] = "GET / HTTP/1.1\r\nHost: examplecat.com\r\n\r\n";

  tun = openTun("tun0");
  conn("208.94.117.43", 80, tun, &c);

  // SYN
  tcpsend(&c, TCP_SYN, "", 0);

  // SYNACK
  tcprecv(&c, recv);
  tcphdr synack = recv->tcp.hdr;
  c.seq = ntohl(synack.ack);
  c.ack = ntohl(synack.seq) + 1;

  // ACK
  tcpsend(&c, TCP_ACK, "", 0);
  c.state = ESTABLISHED;

  // Sending GET request
  tcpsenddata(&c, data, sizeof(data) - 1);

  // Receiving response
  while (c.state != CLOSED && c.rcvd.available == 0) {
    tcphandle(&c);
  }
  printf("%s", c.rcvd.buf);

  // Abrupt close connection
  tcpsend(&c, TCP_RST, "", 0);

  close(tun);
  return 0;
}
