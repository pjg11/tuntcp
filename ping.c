#include "tuntcp.h"

int main(int argc, char *argv[]) {

  int tun, seq;
  int nbytes;
  char *dst;
  packet s, r, *send, *recv;
  struct timespec start, end;
  double elapsed;

  char data[] = "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d"
                "\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
                "\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29"
                "\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37";
  int datalen = sizeof(data) - 1;

  if (argc != 2) {
    printf("Usage: ./ping <ip>\n");
    return 1;
  }

  tun = openTun("tun0");
  seq = 1;
  dst = argv[1];

  send = &s;
  recv = &r;

  printf("PING %s (%s) %d bytes of data.\n", dst, dst, datalen);

  while (1) {
    nbytes = echo(dst, seq, data, datalen, send);

    clock_gettime(CLOCK_REALTIME, &start);

    write(tun, send, nbytes);
    nbytes = read(tun, recv, nbytes);

    clock_gettime(CLOCK_REALTIME, &end);
    elapsed = (end.tv_sec - start.tv_sec) +
              ((end.tv_nsec - start.tv_nsec) / 1000000.0);

    if (!recv->ping.echo.type && elapsed > 0.0) {
      printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", nbytes - 20,
             dst, ntohs(recv->ping.echo.seq), recv->ping.ip.ttl, elapsed);
      seq += 1;
      sleep(1);
    }
  }
  return 0;
}
