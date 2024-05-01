#ifndef TUNTCP_H
#define TUNTCP_H

#include <arpa/inet.h>
#include <assert.h>
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

typedef union {
  struct ping {
    iphdr ip;
    icmpecho echo;
    char data[56];
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
} packet;

int echo(char *dst, uint16_t seq, char data[], int datalen, packet *p);
int udp(char *dst, uint16_t sport, uint16_t dport, char *data, int datalen,
        packet *p);

int openTun(char *dev);
void hexdump(const void *data, int len);

#endif // TUNTCP_H
