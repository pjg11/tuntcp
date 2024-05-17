#include "tuntcp.h"

int main(void) {
  int tun, sockfd, err, nbytes;
  char buf[4096], data[] = "GET / HTTP/1.1\r\nHost: examplecat.com\r\n\r\n";

  tun = open_tun("tun0");
  if (tun == -1)
    perror("tuntcp: tun");

  sockfd = tuntcp_socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd == -1)
    perror("tuntcp: socket");

  err = tuntcp_connect(sockfd, tun, "208.94.117.43", 80);
  if (err == -1)
    perror("tuntcp: connect");

  tuntcp_send(sockfd, data, strlen(data));

  while ((nbytes = tuntcp_recv(sockfd, buf, sizeof(buf))) > 0) {
    printf("%s", buf);
  }

  tuntcp_close(sockfd);
  close(tun);
  return 0;
}
