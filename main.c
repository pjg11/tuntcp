#include "tuntcp.h"

int main(void) {
  int tun;
  tcpconn c;
  tcphdr synack;

  tun = openTun("tun0");
  conn("208.94.117.43", 80, tun, &c);

  tcpsend(&c, TCP_SYN);
  tcprecv(&c, &synack);
  c.seq = synack.ack;
  c.ack = htons(ntohs(synack.seq) + 1);

  tcpsend(&c, TCP_ACK);
  c.state = ESTABLISHED;

  tcpsend(&c, TCP_RST);

  close(tun);
  return 0;
}
