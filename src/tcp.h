#ifndef TCP_H_
#define TCP_H_
#include "route.h"
#include "ip.h"
#include "packetio.h"


// /**
//  * @see [POSIX.1-2017:socket](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/socket.html)
//  */
// int __wrap_socket(int domain, int type, int protocol);

// /**
//  * @see [POSIX.1-2017:bind](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/bind.html)
//  */
// int __wrap_bind(int socket, const struct sockaddr* address,
//     socklen_t address_len);

// /**
//  * @see [POSIX.1-2017:listen](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/listen.html)
//  */
// int __wrap_listen(int socket, int backlog);

// /**
//  * @see [POSIX.1-2017:connect](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/connect.html)
//  */
// int __wrap_connect(int socket, const struct sockaddr* address,
//     socklen_t address_len);

// /**
//  * @see [POSIX.1-2017:accept](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/accept.html)
//  */
// int __wrap_accept(int socket, struct sockaddr* address,
//     socklen_t* address_len);

// /**
//  * @see [POSIX.1-2017:read](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/read.html)
//  */
// ssize_t __wrap_read(int fildes, void* buf, size_t nbyte);

// /**
//  * @see [POSIX.1-2017:write](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/write.html)
//  */
// ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte);

// /**
//  * @see [POSIX.1-2017:close](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/close.html)
//  */
// int __wrap_close(int fildes);

// /** 
//  * @see [POSIX.1-2017:getaddrinfo](http://pubs.opengroup.org/onlinepubs/
//  * 9699919799/functions/getaddrinfo.html)
//  */
// int __wrap_getaddrinfo(const char* node, const char* service,
//     const struct addrinfo* hints,
//     struct addrinfo** res);
// int __wrap__freeaddrinfo(addrinfo* ai);

// TCP Status
#define CLOSED 0
#define SYN_RCVD 1
#define SYN_SENT 2
#define LISTEN 3
#define ESTAB 4
#define FIN_WAIT_1 5
#define FIN_WAIT_2 6
#define CLOSE_WAIT 7
#define LAST_ACK 8
#define CLOSING 9
#define TIME_WAIT 10

extern std::mutex status_mutex;
extern std::mutex ack_mutex;
extern std::mutex read_mutex;
extern std::mutex fin_mutex;
extern std::condition_variable cv_estab;
extern std::condition_variable cv_close;
extern std::condition_variable cv_read;

extern std::set<int> alloc_socket;
extern std::map<int,int> socket_status;

struct TCPInitailizer {
    TCPInitailizer();
};

struct ConnRequest {
    int conn_fd;
    in_addr ip;
    in_port_t port;
    tcphdr header;
    ConnRequest(int _conn_fd, in_addr _ip, in_port_t _port, tcphdr& _hdr)
        : conn_fd(_conn_fd), port(_port), header(_hdr)
    {
        ip.s_addr = _ip.s_addr;
    }
};

struct ListenItem {
    int socket;
    sockaddr_in* sockaddr;
    std::vector<ConnRequest> requests;
    ListenItem(int _socket, sockaddr_in* _sockaddr): socket(_socket), sockaddr(_sockaddr){}
};

struct SocketInfo {
    int seq;
    int start_seq;
    int pair_seq;
    int last_len;
    bool waiting_ack;
    bool is_listening;
    sockaddr_in addr;
    sockaddr_in pair_addr;
    std::vector<u_char> buffer;
    SocketInfo() {
        pair_seq = -1;
        last_len = waiting_ack = is_listening = 0;
        addr.sin_addr.s_addr = 0;
        addr.sin_port = 0;
        seq = start_seq = rand() % 65536;
        seq += 1;
    };
};

extern std::mutex msg_mutex;
struct BindManager {
    std::map<int, SocketInfo> bind_list;
    int findFdBySock(sockaddr_in sock, sockaddr_in another_sock);
};

struct ListenManager {
    std::mutex mutex;
    std::vector<ListenItem> listen_items;
};

int TCP_handler(IPpacket&, int);
int statusForward(int, IPpacket&, int, tcphdr&);

void handleSYN(ConnRequest&, sockaddr_in*);
void handle_SYN_ACK(int, IPpacket&, tcphdr&);
int sendWrite(int, size_t, const void*);

void sendFIN(int);
void send_FINACK(int);
void sendACK(int);

void freeSocket(int);

#endif