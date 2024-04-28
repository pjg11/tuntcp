#include "tuntcp.h"

int main(void) {
  packet p;
  char query[] = "\x44\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78"
                 "\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
  size_t datalen = sizeof(query) - 1;
  size_t size = sizeof(p.udp.ip) + sizeof(p.udp.hdr) + datalen;

  memcpy(p.udp.data, query, datalen);
  p.udp.hdr = udp(datalen, 12345, 53);
  p.udp.ip = ip(sizeof(p.udp.hdr) + datalen, PROTO_UDP, "8.8.8.8");
  hexdump(&p, size);
}
