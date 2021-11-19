#ifndef IP_H_
#define IP_H_
#include "arp.h"
#include "route.h"

uint16_t Checksum(const void* vdata, size_t length);

extern IPPacketReceiveCallback IPCallback;
extern struct DevicePool pool;

void startBroadcast();
int sendIPPacket(DevicePool&, const struct in_addr, const struct in_addr, int, const void*, int);
int setIPPacketReceiveCallback(IPPacketReceiveCallback callback);
int setRoutingTable(const struct in_addr dest, const struct in_addr mask,
    const void* nextHopMAC, const char* device);
int myIPCallback(const void* buf, const int len);
bool IsArrive(in_addr);
struct IPpacket {
    struct __attribute__((__packed__)) {
        ip header;
        u_char* payload;
    };
    IPpacket()
    {
        header.ip_off = IP_DF;
        header.ip_ttl = 10;
        header.ip_v = 4;
        header.ip_hl = 5;
        header.ip_tos = 0;
        header.ip_id = 0;
    }
    void ToNetOrder();
    void RecoverOrder();
};
#endif
