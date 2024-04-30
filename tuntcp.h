#ifndef TUNTCP_H
#define TUNTCP_H

#include <arpa/inet.h>
#include <ctype.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

typedef struct {
  uint8_t version_ihl;
  uint8_t tos;
  uint16_t len;
  uint16_t id;
  uint16_t frag_offset;
  uint8_t ttl;
  uint8_t proto;
  uint16_t checksum;
  uint32_t src;
  uint32_t dst;
} iphdr;

typedef struct {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint16_t id;
  uint16_t seq;
} icmpecho;

typedef struct {
  uint16_t sport;
  uint16_t dport;
  uint16_t len;
  uint16_t checksum;
} udphdr;

typedef struct {
  uint32_t src;
  uint32_t dst;
  uint8_t zero;
  uint8_t proto;
  uint16_t plen; // packet length - header + data
} pseudohdr;

typedef struct {
  union {
    struct ping {
      iphdr ip;
      icmpecho echo;
    } ping;
    struct udp {
      iphdr ip;
      udphdr hdr;
      char data[512];
    } udp;
    struct pseudo {
      pseudohdr ip;
      char data[520]; // TCP/UDP header + data
    } pseudo;
  };
} packet;

iphdr ip(size_t len_contents, uint8_t protocol, char *daddr);
icmpecho echo(uint16_t seq);
int udp(char *dst, uint16_t sport, uint16_t dport, char *data, size_t datalen,
        packet *p);

int openTun(char *dev);
uint16_t checksum(void *data, size_t count);
uint16_t l4checksum(void *data, size_t count);
void hexdump(const void *data, size_t size);

#endif // TUNTCP_H
