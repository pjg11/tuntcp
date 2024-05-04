#include "tuntcp.h"

int main(void) {
  packet s, r;
  packet *send = &s, *recv = &r;
  tcphdr *syn, *synack;
  iphdr *recvip;
  uint32_t saddr, daddr;
  int tun;
  tcpconn c;
  int len;

  tun = openTun("tun0");
  len = conn("208.94.117.43", 80, tun, &c);

  // SYN
  len = tcp(c.daddr, c.sport, c.dport, TCP_SYN, c.seq, c.ack, send);
  syn = &send->tcp.hdr;
  hexdump(send, len);
  write(tun, send, len);

  // SYNACK
  len = timeoutread(tun, recv, sizeof(*recv));
  hexdump(recv, len);
  synack = &recv->tcp.hdr;
  recvip = &recv->tcp.ip;
  inet_pton(AF_INET, c.saddr, &saddr);
  inet_pton(AF_INET, c.daddr, &daddr);

  if (recvip->src == daddr && recvip->dst == saddr &&
      c.sport == ntohs(synack->dport) && c.dport == ntohs(synack->sport)) {
    c.seq = synack->ack;
    c.ack = htonl(ntohl(synack->seq) + 1);
    assert(ntohl(c.seq) == ntohl(syn->seq) + 1);

    // ACK
    len = tcp(c.daddr, c.sport, c.dport, TCP_ACK, c.seq, c.ack, send);
    hexdump(send, len);
    write(tun, send, len);

    c.state = ESTABLISHED;

    // RST
    len = tcp(c.daddr, c.sport, c.dport, TCP_RST, c.seq, c.ack, send);
    hexdump(send, len);
    write(tun, send, len);
  }

  close(tun);
  return 0;
}
