#include "tuntcp.h"

int main(int argc, char *argv[]) {
  int tun, count, len;
  double elapsed;
  char *dst;
  packet send, recv;
  struct ping *s, *r;
  struct timespec start, end;

  if (argc != 2) {
    printf("Usage: ./ping <ip>\n");
    return 1;
  }

  tun = openTun("tun0");
  count = 1;
  dst = argv[1];

  s = &send.ping;
  s->ip = ip(sizeof(s->echo), PROTO_ICMP, dst);

  printf("PING %s (%s) %d bytes of data.\n", dst, dst, ntohs(s->ip.len));

  while (1) {
    s->echo = echo(count);

    clock_gettime(CLOCK_REALTIME, &start);

    write(tun, &send, sizeof(send));
    len = read(tun, &recv, sizeof(recv));

    clock_gettime(CLOCK_REALTIME, &end);
    elapsed = (end.tv_sec - start.tv_sec) +
              ((end.tv_nsec - start.tv_nsec) / 1000000.0);

    r = &recv.ping;
    if (!r->echo.type && elapsed > 0) {
      printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.1f ms\n", len, dst,
             ntohs(r->echo.seq), r->ip.ttl, elapsed);
      count += 1;
      sleep(1);
    }
  }
  return 0;
}
