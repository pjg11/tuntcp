#include "tuntcp.h"

int main(void) {
  packet s, r;
  packet *send = &s, *recv = &r;
  tcphdr *syn, *synack;
  int tun;
  int len;

  tun = openTun("tun0");

  // SYN
  len = tcp("208.94.117.43", 12346, 80, TCP_SYN, 0, 0, send);
  syn = &send->tcp.hdr;
  hexdump(send, len);
  write(tun, send, len);

  // SYNACK
  len = timeoutread(tun, recv, sizeof(*recv));
  hexdump(recv, len);
  synack = &recv->tcp.hdr;
  assert(ntohl(synack->ack) == ntohl(syn->seq) + 1);

  // ACK
  len = tcp("208.94.117.43", 12346, 80, TCP_ACK, ntohl(synack->ack),
            ntohl(synack->seq) + 1, send);
  hexdump(send, len);
  write(tun, send, len);

  // RST
  len = tcp("208.94.117.43", 12346, 80, TCP_RST, ntohl(synack->ack),
            ntohl(synack->seq) + 1, send);
  hexdump(send, len);
  write(tun, send, len);
  return 0;
}
