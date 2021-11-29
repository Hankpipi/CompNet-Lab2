#include "../checkpoints/unp.h"

#define MAX_READ_LINE 50000
void str_echo(int sockfd) {
  ssize_t n;
  char buf[MAX_READ_LINE];
  size_t acc = 0;
  again:
  while ((n = read(sockfd, buf, MAX_READ_LINE)) > 0) {
    acc += n;
    printf("[Server] tot_receive %zu\n", acc);
    fflush(stdout);
    sleep(10);
  }
  printf("[Server] receive done, all: %zu\n", acc);
  if (n < 0 && errno == EINTR) {
    goto again;
  } else if (n < 0) {
    printf("str_echo: read error\n");
  }
}

int main(int argc, char *argv[]) {
    struct sockaddr_in cliaddr, servaddr;
    int listenfd = Socket(AF_INET, SOCK_STREAM, 0);
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
