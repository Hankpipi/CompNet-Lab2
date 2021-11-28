#include "../checkpoints/unp.h"

void str_echo(int sockfd) {
  ssize_t n;
  char buf[MAXLINE];
  size_t acc = 0;
  again:
  while ((n = read(sockfd, buf, MAXLINE)) > 0) {
    writen(sockfd, buf, n);
    acc += n;
    printf("%zu ", acc);
    fflush(stdout);
    sleep(3);
  }
  printf("all: %zu\n", acc);
  if (n < 0 && errno == EINTR) {
    goto again;
  } else if (n < 0) {
    printf("str_echo: read error\n");
  }
  close(sockfd);
}

int main(int argc, char *argv[]) {
    struct sockaddr_in cliaddr, servaddr;
    int listenfd = Socket(AF_INET, SOCK_STREAM, 0);
    int optval;
    int rv;
    int connfd;
    
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(10086);

    Bind(listenfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
    Listen(listenfd, SOMAXCONN);

    socklen_t clilen = sizeof(cliaddr);
    connfd = Accept(listenfd, (struct sockaddr *) &cliaddr, &clilen);
    printf("new connection\n");
    str_echo(connfd);
  return 0;
}
