#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>
#include <ctype.h>

#define PROTO_ICMP 1
#define PROTO_TCP 6
#define PROTO_UDP 17

typedef struct {
  uint8_t  version_ihl;
  uint8_t  tos;
  uint16_t len;
  uint16_t id;
  uint16_t frag_offset;
  uint8_t  ttl;
  uint8_t  proto;
  uint16_t checksum;
  uint32_t src;
  uint32_t dst;
} ipv4;

// https://www.rfc-editor.org/rfc/rfc1071#section-4.1
uint16_t checksum(void *data, size_t count) {

  register uint32_t sum = 0;
  uint16_t *p = data;

  while (count > 1)  {
    sum += *p++;
    count -= 2;
  }

  if (count > 0)
    sum += * (uint8_t *) data;

  while (sum >> 16)
    sum = (sum & 0xffff) + (sum >> 16);

  return ~sum;
}

ipv4 ip(size_t len_contents, uint8_t protocol, char *daddr) {

  ipv4 i;

  i.version_ihl = 4 << 4 | 5;
  i.tos = 0;
  i.len = htons(20 + len_contents);
  i.id = htons(1);
  i.frag_offset = 0;
  i.ttl = 64;
  i.proto = protocol;
  i.checksum = 0;
  inet_pton(AF_INET, "192.0.2.2", &i.src);
  inet_pton(AF_INET, daddr, &i.dst);

  i.checksum = checksum(&i, sizeof(i));
  return i;
}

// https://github.com/pandax381/microps/blob/ac3747f68a6fd590443d028b4eaf5d97c4c58e49/util.c#L38
void hexdump(const void *data, size_t size) {
  unsigned char *src;
  int offset, index;

  src = (unsigned char *)data;
  for(offset = 0; offset < (int)size; offset += 16) {
    printf("%08x ", offset);
    for(index = 0; index < 16; index++) {
      if ((offset + index) % 8 == 0)
        printf(" ");

      if(offset + index < (int)size) {
        printf("%02x ", 0xff & src[offset + index]);
      } else {
        printf("   ");
      }
    }
    printf(" |");
    for(index = 0; index < 16; index++) {
      if(offset + index < (int)size) {
        if(isascii(src[offset + index]) && isprint(src[offset + index])) {
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
}

int openTun(char *dev) {
  int fd, err;
  struct ifreq ifr;

  if((fd = open("/dev/net/tun", O_RDWR)) < 0)
    return 1;

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  strncpy(ifr.ifr_name, dev, IFNAMSIZ);

  if((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
    close(fd);
    return err;
  }
  return fd;
}

int main(void) {
  int tun = openTun("tun0");
  ipv4 i = ip(0, PROTO_ICMP, "208.94.117.43");
  hexdump(&i, sizeof(i));

  close(tun);
  return 0;
}
