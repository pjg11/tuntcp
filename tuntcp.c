#include "tuntcp.h"

tcpconn sockets[1];

int open_tun(char *dev) {
  int fd, err;
  struct ifreq ifr;

  if ((fd = open("/dev/net/tun", O_RDWR)) < 0)
    return -1;

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
    close(fd);
    return err;
  }
  return fd;
}

// https://stackoverflow.com/a/2918709
int timeoutread(int fd, void *buf, size_t count) {
  int rv;
  fd_set set;
  struct timeval tv;

  FD_ZERO(&set);
  FD_SET(fd, &set);

  tv.tv_sec = 5;
  tv.tv_usec = 0;
  rv = select(fd + 1, &set, NULL, NULL, &tv);

  if (rv == -1)
    perror("select");
  else if (rv == 0)
    printf("timeout\n");
  else
    return read(fd, buf, count);

  return -1;
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

// https://www.rfc-editor.org/rfc/rfc1071#section-4.1
uint16_t checksum(void *data, int len) {
  register uint32_t sum = 0;
  uint16_t *p = data;

  while (len > 1) {
    sum += *p++;
    len -= 2;
  }

  if (len > 0)
    sum += *(uint8_t *)p;

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

// TCP/UDP checksum
uint16_t l4checksum(void *data, int len) {
  packet p;
  iphdr *i = (iphdr *)data;

  // Pseudoheader
  p.pseudo.ip.src = i->saddr;
  p.pseudo.ip.dst = i->daddr;
  p.pseudo.ip.zero = 0;
  p.pseudo.ip.proto = i->proto;
  p.pseudo.ip.plen = htons(len);

  // TCP/UDP header + data
  memcpy(p.pseudo.data, (char *)data + sizeof(*i), len);

  return checksum(&p, sizeof(p.pseudo.ip) + len);
}

int ip(int datalen, uint8_t protocol, tcpconn *c, iphdr *i) {
  int len = sizeof(*i);

  i->version_ihl = 4 << 4 | 5;
  i->tos = 0;
  i->len = htons(20 + datalen);
  i->id = htons(1);
  i->frag_offset = 0;
  i->ttl = 64;
  i->proto = protocol;
  i->checksum = 0;
  i->saddr = htonl(c->saddr);
  i->daddr = htonl(c->daddr);

  i->checksum = checksum(i, len);
  return len;
}

int echo(uint16_t seq, char data[], int datalen, tcpconn *c, packet *p) {
  int len;

  // Echo request
  icmpecho *e = &p->ping.echo;
  e->type = 8;
  e->code = 0;
  e->checksum = 0;
  e->id = htons(12345);
  e->seq = htons(seq);
  len = sizeof(*e);

  // Data
  memcpy(&p->ping.data, data, datalen);
  len += datalen;

  // ICMP Checksum
  e->checksum = checksum((char *)p + sizeof(p->ping.ip), len);

  // IP header
  ip(len, PROTO_ICMP, c, &p->ping.ip);

  return sizeof(p->ping.ip) + len;
}

int udp(char *data, int datalen, tcpconn *c, packet *p) {
  int len;

  // UDP header
  udphdr *u = &p->udp.hdr;
  u->sport = htons(c->sport);
  u->dport = htons(c->dport);
  u->len = htons(8 + datalen);
  u->checksum = 0;
  len = sizeof(*u);

  // UDP data
  memcpy(&p->udp.data, data, datalen);
  len += datalen;

  // IP header
  ip(len, PROTO_UDP, c, &p->udp.ip);

  // UDP Checksum
  u->checksum = l4checksum(&p->udp, len);

  return sizeof(p->udp.ip) + len;
}

int tcp(uint8_t flags, char *data, int datalen, tcpconn *c, packet *p) {

  // TCP header
  tcphdr *t = &p->tcp.hdr;
  int len = flags & TCP_SYN ? 24 : sizeof(*t);
  int optionslen = 0;

  t->sport = htons(c->sport);
  t->dport = htons(c->dport);
  t->seq = htonl(c->seq);
  t->ack = htonl(c->ack);
  t->rsvd_offset = (len / 4) << 4;
  t->flags = flags;
  t->win = htons(65535);
  t->checksum = 0;
  t->urp = 0;

  // Maximum Segment Size
  if (flags & TCP_SYN) {
    optionslen = 4;
    memcpy(&p->tcp.data, "\x02\x04\x05\xb4", optionslen);
  }

  // TCP Data
  memcpy(&p->tcp.data + optionslen, data, datalen);
  len += datalen;

  // IP header
  ip(len, PROTO_TCP, c, &p->tcp.ip);

  // TCP Checksum
  t->checksum = l4checksum(&p->tcp, len);

  return sizeof(p->tcp.ip) + len;
}

int conn(struct sockaddr *addr, int tunfd, tcpconn *c) {
  struct sockaddr_in *address = (struct sockaddr_in *)addr;
  srand(time(NULL));

  c->tunfd = tunfd;
  c->state = CLOSED;

  inet_pton(AF_INET, "192.0.2.2", &c->saddr);
  c->saddr = ntohl(c->saddr);
  c->sport = (uint16_t)rand();

  c->daddr = ntohl(address->sin_addr.s_addr);
  c->dport = ntohs(address->sin_port);

  c->seq = (uint32_t)rand();
  c->ack = 0;

  c->rcvd.readptr = 0;
  c->rcvd.available = 0;

  return sizeof(*c);
}

int tcpsend(tcpconn *c, uint8_t flags, char *data, int datalen) {
  packet s, *send = &s;
  int len = tcp(flags, data, datalen, c, send);

  c->seq += datalen;
  return write(c->tunfd, send, len);
}

int tcprecv(tcpconn *c, packet *recv) {
  while (1) {
    int len = timeoutread(c->tunfd, recv, sizeof(*recv));

    iphdr *i = &recv->tcp.ip;
    tcphdr *t = &recv->tcp.hdr;

    if (ntohl(i->saddr) == c->daddr && ntohl(i->daddr) == c->saddr &&
        c->sport == ntohs(t->dport) && c->dport == ntohs(t->sport)) {
      return len;
    }
  }
}

int tcpsenddata(tcpconn *c, char data[], int datalen) {
  int len = datalen, mss = 1460, seglen = 0;

  while (len > 0) {
    seglen = len > mss ? mss : len;
    tcpsend(c, TCP_PSH | TCP_ACK, data, seglen);
    len -= seglen;
  }

  // TODO: Implement retry
  return 0;
}

int tcphandle(tcpconn *c) {
  packet r;
  int len = tcprecv(c, &r);
  int datalen = len - sizeof(r.tcp.ip) - sizeof(r.tcp.hdr);

  if (ntohl(r.tcp.hdr.seq) != c->ack)
    return 0;

  if (c->state == ESTABLISHED && datalen > 0) {
    memcpy(c->rcvd.buf + c->rcvd.available, r.tcp.data, datalen);
    c->rcvd.available += datalen;
    c->ack = ntohl(r.tcp.hdr.seq) + datalen;
    tcpsend(c, TCP_ACK, "", 0);
    return datalen;
  }

  if (r.tcp.hdr.flags & TCP_FIN)
    c->state = CLOSED;

  return 0;
}

int tcprecvdata(tcpconn *c, char data[], int datalen) {
  int nbytes = 0;
  while (c->state != CLOSED && c->rcvd.available == 0) {
    nbytes += tcphandle(c);
  }
  memcpy(data, c->rcvd.buf + c->rcvd.readptr, datalen);
  c->rcvd.readptr += datalen;
  return nbytes;
}

int tuntcp_socket(int domain, int type, int protocol) {
  // TODO: Implement multiple sockets, return 1 for now
  return 0;
}

int tuntcp_connect(int sockfd, int tunfd, struct sockaddr *addr, int addrlen) {
  packet r, *recv = &r;
  tcpconn *c = &sockets[sockfd];
  conn(addr, tunfd, c);

  // SYN
  tcpsend(c, TCP_SYN, "", 0);

  // SYNACK
  tcprecv(c, recv);
  tcphdr synack = recv->tcp.hdr;
  c->seq = ntohl(synack.ack);
  c->ack = ntohl(synack.seq) + 1;

  // ACK
  tcpsend(c, TCP_ACK, "", 0);
  c->state = ESTABLISHED;

  return 0;
}

ssize_t tuntcp_send(int sockfd, void *buf, size_t len) {
  tcpconn *c = &sockets[sockfd];
  return tcpsenddata(c, buf, len);
}

ssize_t tuntcp_recv(int sockfd, void *buf, size_t len) {
  tcpconn *c = &sockets[sockfd];
  return tcprecvdata(c, buf, len);
}

int tuntcp_close(int sockfd) {
  // TODO: Implement proper connection closing
  tcpconn *c = &sockets[sockfd];
  tcpsend(c, TCP_RST, "", 0);
  return 0;
}
