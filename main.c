#include "tuntcp.h"

int main(void) {
  packet p, recv;
  char query[] = "\x44\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78"
                 "\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
  size_t datalen = sizeof(query);
  size_t ipdatasize = sizeof(p.udp.hdr) + datalen;
  size_t total = sizeof(p.udp.ip) + ipdatasize;
  int tun = openTun("tun0");

  memcpy(p.udp.data, query, datalen);
  p.udp.hdr = udp(datalen, 12345, 53);
  p.udp.ip = ip(ipdatasize, PROTO_UDP, "8.8.8.8");

  pseudohdr ph;
  ph.src = p.udp.ip.src;
  ph.dst = p.udp.ip.dst;
  ph.zero = 0;
  ph.proto = PROTO_UDP;
  ph.plen = htons(ipdatasize);

  packet q;
  q.pseudo.ip = ph;
  memcpy(q.pseudo.data, (char *)&p.udp + 20, ipdatasize);

  p.udp.hdr.checksum = checksum(&q, sizeof(ph) + ipdatasize);

  hexdump(&p, total);
  printf("\n");

  write(tun, &p, total);
  int bytes = read(tun, &recv, 540);
  
  hexdump(&recv.udp, bytes);
  printf("\n");
  
  // Printing the received address for example.com
  hexdump((char *)&recv.udp.data + 41, 4);
  return 0;
}
