#include "arp.h"

std::mutex condition_mutex;
std::map<const u_char*, uint8_t, cmp_str> status;
std::map<const in_addr, char *, cmp_ip> arp_map;

arpPacket::arpPacket(const void* buf) {
    memcpy(this, buf, sizeof(arpPacket));
    this->RecoverOrder();
}

arpPacket::arpPacket() {
    header.ar_hrd = ARPHRD_ETHER;
    header.ar_pro = ETHERTYPE_IP;
    header.ar_hln = ETHER_ADDR_LEN;
    header.ar_pln = 4;
}

void arpPacket::ToNetOrder() {
    header.ar_hrd = htons(header.ar_hrd);
    header.ar_pro = htons(header.ar_pro);
    header.ar_op = htons(header.ar_op);
}

void arpPacket::RecoverOrder() {
    header.ar_hrd = ntohs(header.ar_hrd);
    header.ar_pro = ntohs(header.ar_pro);
    header.ar_op = ntohs(header.ar_op);
}

char* ARPFindMAC(Device* dev, in_addr target_ip) {
    if (arp_map.find(target_ip) != arp_map.end()) {
        printf("[ARPFindMAC] [targetIP: %s] is in arp_map [MAC: %s]\n", IPtoStr(target_ip), arp_map.at(target_ip));
        return arp_map.at(target_ip);
    }
    printf("[ARPFindMAC] [sendARPRequest] [targetIP: %s] [device_name: %s]\n", IPtoStr(target_ip), dev->name);
    sendARPRequest(dev, target_ip);
    double total_wait_time = 0;
    int retry = 0;
    printf("[ARPFindMAC] start arp looping\n");
    while (1) {
        usleep(250000);
        total_wait_time += 0.25;
        condition_mutex.lock();
        if (arp_map.find(target_ip) != arp_map.end()) {
            condition_mutex.unlock();
            return arp_map.at(target_ip);
        } 
        condition_mutex.unlock();
        if (total_wait_time > MAX_ARP_WATING_TIME) {
            total_wait_time = 0;
            retry += 1;            
            if (retry > MAX_ARP_RESEND)
                throw "findARP failed! Please check your IP and network connection";

            printf("[ARPFindMAC] [Resend ARPRequest] [Retry = %d] [targetIP: %s] [device_name: %s]\n",
                    retry, IPtoStr(target_ip), dev->name);
            sendARPRequest(dev, target_ip);
        }
    }
}

void sendARPRequest(Device* dev, in_addr target_ip) {
    arpPacket request;
    memset(request.dstMac, 0, sizeof(request.dstMac));
    request.header.ar_op = ARPOP_REQUEST;
    request.srcIP = dev->ip;
    StrToMac(dev->mac, request.srcMac);
    request.dstIP = target_ip;
    request.ToNetOrder();
    dev->sendFrame(&request, sizeof(request), ETHERTYPE_ARP, "ff:ff:ff:ff:ff:ff");
}

void handleARPRequest(Device* dev, arpPacket& pkt) {
    printf("[handleARPRequest]: ...\n");
    if (pkt.dstIP.s_addr != dev->ip.s_addr)
        return;
    arpPacket reply;
    reply.header.ar_op = ARPOP_REPLY;
    reply.srcIP = pkt.dstIP;
    reply.dstIP = pkt.srcIP;
    u_char mac[6];
    StrToMac(dev->mac, mac);
    memcpy(reply.srcMac, mac, sizeof(mac));
    memcpy(reply.dstMac, pkt.srcMac, sizeof(pkt.srcMac));
    reply.ToNetOrder();
    printf("[handleARPRequest] [srcIP=%s] [dstIP=%s]\n", IPtoStr(reply.srcIP), IPtoStr(reply.dstIP));
    dev->sendFrame(&reply, sizeof(reply), ETHERTYPE_ARP, MacToStr(pkt.srcMac));
}

void handleARPReply(const void* buf, int len, char* targetMAC) {
    arpPacket pkt(buf);
    in_addr targetIP = pkt.srcIP;
    printf("[handleARPReply] arp_map[%s] = %s\n", IPtoStr(targetIP), targetMAC);
    condition_mutex.lock();
    arp_map[targetIP] = targetMAC;
    condition_mutex.unlock();
}
