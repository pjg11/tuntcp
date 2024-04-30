#include "tuntcp.h"

int main(void) {
  packet send, recv;
  int tun = openTun("tun0"), bytes;
  // DNS query for example.com
  char data[] = "\x44\xcb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78"
                "\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01";
  size_t datalen = sizeof(data);

  bytes = udp("8.8.8.8", 12345, 53, data, datalen, &send);

  hexdump(&send, bytes);
  printf("\n");

  write(tun, &send, bytes);
  bytes = read(tun, &recv, 540);

  hexdump(&recv.udp, bytes);
  printf("\n");

  // Printing the received address for example.com
  hexdump((char *)&recv.udp.data + 41, 4);
  return 0;
}
