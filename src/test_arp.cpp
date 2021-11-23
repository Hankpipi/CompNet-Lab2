#include "arp.h"
#include "packetio.h"
#include "ip.h"

int main() {
    char* errbuf = NULL;
    pcap_if_t * pcap_it;
    if(pcap_findalldevs(&pcap_it, errbuf) < 0) {
        my_printf("findalldevs error: %s", errbuf);
        return 0;
    }
    //pool define in ip.cpp
    pool.setFrameReceiveCallback(myFrameReceivedCallback);
    setIPPacketReceiveCallback(myIPCallback);

    for (pcap_if_t* it = pcap_it; it; it = it->next) {
        if(pool.addDevice(it->name) < 0) {
            continue;
        }
    }

    while (1) {
        // 10.100.1.1; 10.100.1.2
        in_addr src, dst;
        inet_aton("10.100.1.1", &src);
        inet_aton("10.100.1.2", &dst);
        u_char buf[13] = "hello, world";
        sendIPPacket(pool, src, dst, IPPROTO_UDP, buf, 12);
        sleep(100);
    }

    return 0;
}