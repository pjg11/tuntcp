#include "tuntcp.h"

// https://www.rfc-editor.org/rfc/rfc1071#section-4.1
uint16_t checksum(void *data, int count) {
  register uint32_t sum = 0;
  uint16_t *p = data;

  while (count > 1) {
    sum += *p++;
    count -= 2;
  }

  if (count > 0)
    sum += *(uint8_t *)data;

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

// TCP/UDP checksum
uint16_t l4checksum(void *data, int count) {
  packet p;
  iphdr i = *(iphdr *)data;

  // Pseudoheader
  p.pseudo.ip.src = i.src;
  p.pseudo.ip.dst = i.dst;
  p.pseudo.ip.zero = 0;
  p.pseudo.ip.proto = i.proto;
  p.pseudo.ip.plen = htons(count);

  // TCP/UDP header + data
  memcpy(p.pseudo.data, (char *)data + 20, count);

  return checksum(&p, sizeof(p.pseudo.ip) + count);
}

void ip(int datalen, uint8_t protocol, char *daddr, iphdr *i) {
  i->version_ihl = 4 << 4 | 5;
  i->tos = 0;
  i->len = htons(20 + datalen);
  i->id = htons(1);
  i->frag_offset = 0;
  i->ttl = 64;
  i->proto = protocol;
  i->checksum = 0;
  inet_pton(AF_INET, "192.0.2.2", &i->src);
  inet_pton(AF_INET, daddr, &i->dst);

  i->checksum = checksum(i, sizeof(*i));
}

int echo(char *dst, uint16_t seq, char data[], int datalen, packet *p) {
  int len = 8;

  // Echo request
  icmpecho *e = &p->ping.echo;
  e->type = 8;
  e->code = 0;
  e->checksum = 0;
  e->id = htons(12345);
  e->seq = htons(seq);

  // Data
  memcpy(&p->ping.data, data, datalen);
  len += datalen;

  // Checksum
  p->ping.echo.checksum = checksum((char *)p + sizeof(p->ping.ip), len);

  // IP header
  ip(len, PROTO_ICMP, dst, &p->ping.ip);
  len += sizeof(p->ping.ip);

  return len;
}

int udp(char *dst, uint16_t sport, uint16_t dport, char *data, int datalen,
        packet *p) {
  int len = 0, udplen = 8 + datalen;

  // UDP header
  p->udp.hdr.sport = htons(sport);
  p->udp.hdr.dport = htons(dport);
  p->udp.hdr.len = htons(8 + datalen);
  p->udp.hdr.checksum = 0;
  len = 8;

  // UDP data
  memcpy(&p->udp.data, data, datalen);
  len += datalen;

  // IP header
  ip(udplen, PROTO_UDP, dst, &p->udp.ip);
  len += sizeof(p->udp.ip);

  // Checksum calculation
  p->udp.hdr.checksum = l4checksum(&p->udp, udplen);

  return len;
}

int openTun(char *dev) {
  int fd, err;
  struct ifreq ifr;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    return 1;

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }
  return fd;
}

// https://github.com/pandax381/microps/blob/ac3747f68a6fd590443d028b4eaf5d97c4c58e49/util.c#L38
void hexdump(const void *data, int nbytes) {
  unsigned char *src;
  int offset, index;

  src = (unsigned char *)data;
  for (offset = 0; offset < (int)nbytes; offset += 16) {
    printf("%08x ", offset);
    for (index = 0; index < 16; index++) {
      if ((offset + index) % 8 == 0)
        printf(" ");

      if (offset + index < (int)nbytes) {
        printf("%02x ", 0xff & src[offset + index]);
      } else {
        printf("   ");
      }
    }
    printf(" |");
    for (index = 0; index < 16; index++) {
      if (offset + index < (int)nbytes) {
        if (isascii(src[offset + index]) && isprint(src[offset + index])) {
          printf("%c", src[offset + index]);
        } else {
          printf(".");
        }
      } else {
        printf(" ");
      }
    }
    printf("|\n");
  }
  printf("\n");
}
