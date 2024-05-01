#include "tuntcp.h"

int main(void) {
  packet s, r;
  packet *send = &s, *recv = &r;
  int tun;
  int len;

  // DNS query for examplecat.com
  char data[] = "\xcb\xcc\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0a\x65\x78"
                "\x61\x6d\x70\x6c\x65\x63\x61\x74\x03\x63\x6f\x6d\x00\x00\x01"
                "\x00\x01";

  tun = openTun("tun0");
  len = udp("8.8.8.8", 12345, 53, data, sizeof(data) - 1, send);

  hexdump(send, len);

  write(tun, send, len);
  len = read(tun, recv, 540);

  hexdump(recv, len);

  // Checking the received address for example.com
  char addr[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, (char *)recv->udp.data + 44, addr, INET_ADDRSTRLEN);
  assert(strcmp(addr, "208.94.117.43") == 0);
  return 0;
}
