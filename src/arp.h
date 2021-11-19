#ifndef ARP_H_
#define ARP_H_
#include "device.h"

char* ARPFindMAC(Device* dev, in_addr target_ip);
void sendARPRequest(Device* dev, in_addr target_ip);
struct arpPacket {
    struct __attribute__((__packed__)) {
        arphdr header;
        u_char srcMac[6];
        u_char dstMac[6];
        in_addr srcIP;
        in_addr dstIP;
    };
    arpPacket(const void* buf);
    arpPacket();
    void ToNetOrder();
    void RecoverOrder();
};
void handleARPRequest(Device* dev, arpPacket& pkt);
void handleARPReply(const void* buf, int len, char* targetMAC);
#endif
