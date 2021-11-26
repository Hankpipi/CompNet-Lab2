#include <condition_variable>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#else
#include <netpacket/packet.h>
#endif
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <unistd.h>
#include <assert.h>
#include <iostream>
#include <cstring>
#include <cstdio>
#include <vector>
#include <chrono>
#include <thread>
#include <mutex>
#include <map>
#include <set>

// #define DEBUG_TCP
#ifdef DEBUG_TCP
#define my_printf printf
#else
#define my_printf(...)
#endif

// #define DEBUG_IP
#ifdef DEBUG_IP
#define IP_printf printf
#else
#define IP_printf(...)
#endif

// #define DEBUG_LINK
#ifdef DEBUG_LINK
#define LK_printf printf
#else
#define LK_printf(...)
#endif

#define MAX_ARP_WATING_TIME 5
#define MAX_ARP_RESEND 5
#define ROUTER_REMAIN_TIME 6
#define CHECK_GAP_TIME 5
#define ROUTE_PROTO 0xffff
#define SOCKET_MIN  0
#define SOCKET_MAX 2147483647
#define MAX_TCP_RETRY_NUM 8
#define MAX_WRITE_SIZE 10000

typedef int (*frameReceiveCallback)( const void *, int , int );
typedef int (*IPPacketReceiveCallback)(const void* , int);
u_char* MacToStr(const u_char* mac);
void StrToMac(const u_char* str, u_char* dst);

// IP Basic
char* IPtoStr(in_addr IP);
u_char* GetMACAddr(const char* name);
struct cmp_ip {
    bool operator()(const in_addr ip1, const in_addr ip2) const;
};
struct cmp_str {
    bool operator()(const u_char *a, const u_char *b) const;
};
bool IsSameSubnet(in_addr, in_addr, in_addr );
int GetIPInfo(const char* dev_name, in_addr& dev_ip, in_addr& subnetMask);

// TCP Basic
void TCPToHost(tcphdr&);
void TCPToNet(tcphdr&);
bool check_SYN(tcphdr&);
bool check_SYN_ACK(tcphdr&);
bool check_ACK(tcphdr&);
bool check_FIN(tcphdr&);
