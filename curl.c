#include "tuntcp.h"

int main(int argc, char *argv[]) {
  int tun, sockfd, err, nbytes;
  char *port, buf[4096], *data, ipstr[INET_ADDRSTRLEN];
  struct sockaddr_in *addr;
  struct addrinfo hints, *res;

  switch (argc) {
  case 2:
    port = "80";
    break;
  case 3:
    port = argv[2];
    break;
  default:
    printf("Usage: ./curl <host> [port]\n");
    return 1;
  }

  tun = open_tun("tun0");
  if (tun == -1)
    perror("tuntcp: tun");

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  char *e = strchr(argv[1], '/');
  char *path;
  size_t index = (size_t)(e - argv[1]);
  if (index > strlen(argv[1])) {
    path = "";
  } else {
    argv[1][index] = '\0';
    path = argv[1] + index + 1;
  }

  err = getaddrinfo(argv[1], port, &hints, &res);
  if (err)
    perror(gai_strerror(err));

  addr = (struct sockaddr_in *)res->ai_addr;
  inet_ntop(res->ai_family, &(addr->sin_addr), ipstr, sizeof(ipstr));

  data = calloc(26 + strlen(argv[1]) + strlen(path), sizeof(char));
  sprintf(data, "GET /%s HTTP/1.1\r\nHost: %s\r\n\r\n", path, argv[1]);

  sockfd = tuntcp_socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sockfd == -1)
    perror("tuntcp: socket");

  err = tuntcp_connect(sockfd, tun, ipstr, atoi(port));
  if (err == -1)
    perror("tuntcp: connect");

  tuntcp_send(sockfd, data, strlen(data));

  while ((nbytes = tuntcp_recv(sockfd, buf, sizeof(buf))) > 0) {
    char *resp = strstr(buf, "\r\n\r\n");
    if (resp != NULL) {
      resp += 4;
      printf("%s", resp);
    }
  }

  tuntcp_close(sockfd);
  close(tun);
  free(data);
  return 0;
}
