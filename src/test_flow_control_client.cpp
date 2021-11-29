#include "../checkpoints/unp.h"

const char* message = "";

#define MSG_LEN 250000
#define _MAXLINE 10001
char message_buf[MSG_LEN];

void populate_buf() {
  int i;
  int message_len = strlen(message);
  memcpy(message_buf, message, message_len);
  i = message_len;
  while (i + 1 < MSG_LEN) {
    if(i % 10000 == 0 && i != 0)
        message_buf[i] = '\n';
    else
        message_buf[i] = 'a' + (i % 26);
    i += 1;
  }
  message_buf[i] = '\n';
}

void str_cli(FILE *fp, int sockfd) {
  char sendline[_MAXLINE];
  char recvline[_MAXLINE];
  while (fgets(sendline, _MAXLINE, fp) != NULL) {
    int n = writen(sockfd, sendline, strlen(sendline));
    printf("[Client] Send %d\n", n);
    fflush(stdout);
  }
}

void cli_client(const char* addr) {
  int sockfd;
  struct sockaddr_in servaddr;
  FILE* fp;

  sockfd = Socket(AF_INET, SOCK_STREAM, 0);
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_port = htons(10086);
  Inet_pton(AF_INET, addr, &servaddr.sin_addr);
  Connect(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
  populate_buf();
  
  fp = fmemopen(message_buf, MSG_LEN, "r");

  str_cli(fp, sockfd);
  fclose(fp);
}

int main(int argc, char *argv[]) {
  
    if (argc != 2) {
        printf("usage: %s <IPaddress>\n", argv[0]);
        return -1;
    }
  
    cli_client(argv[1]);
    printf("test pass\n");
    return 0;
}
