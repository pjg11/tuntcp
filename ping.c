#include "tuntcp.h"

int main(int argc, char *argv[]) {
  int tun, count, len, size;
  char *dst;
  packet send, recv;
  struct timespec start, end;
  double elapsed;

  if (argc != 2) {
    printf("Usage: ./ping <ip>\n");
    return 1;
  }

  tun = openTun("tun0");
  count = 1;
  dst = argv[1];

  send.ping.ip = ip(sizeof(send.ping.echo), PROTO_ICMP, dst);
  size = sizeof(send.ping);
  printf("PING %s (%s) %d bytes of data.\n", dst, dst, ntohs(send.ping.ip.len));

  while (1) {
    send.ping.echo = echo(count);

    clock_gettime(CLOCK_REALTIME, &start);

    write(tun, &send, size);
    len = read(tun, &recv, size);

    clock_gettime(CLOCK_REALTIME, &end);
    elapsed = (end.tv_sec - start.tv_sec) +
              ((end.tv_nsec - start.tv_nsec) / 1000000.0);

    if (!recv.ping.echo.type && elapsed > 0.0) {
      printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", len, dst,
             ntohs(recv.ping.echo.seq), recv.ping.ip.ttl, elapsed);
      count += 1;
      sleep(1);
    }
  }
  return 0;
}
