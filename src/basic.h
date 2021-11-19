#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#ifdef __APPLE__
#include <net/if_dl.h>
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
#include <thread>
#include <mutex>
#include <map>
#include <set>

#define MAX_ARP_WATING_TIME 5
#define MAX_ARP_RESEND 5
#define ROUTER_REMAIN_TIME 6
#define CHECK_GAP_TIME 5
#define ROUTE_PROTO 0xffff

typedef int (*frameReceiveCallback)( const void *, int , int );
typedef int (*IPPacketReceiveCallback)(const void* , int);
u_char* MacToStr(const u_char* mac);
void StrToMac(const u_char* str, u_char* dst);
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
