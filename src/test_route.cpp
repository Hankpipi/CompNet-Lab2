#include "packetio.h"
#include "ip.h"
#include "route.h"

int main() {
    char* errbuf = NULL;
    pcap_if_t * pcap_it;
    if(pcap_findalldevs(&pcap_it, errbuf) < 0) {
        my_printf("findalldevs error: %s", errbuf);
        return 0;
    }
    //pool define in device.cpp
    pool.setFrameReceiveCallback(myFrameReceivedCallback);
    setIPPacketReceiveCallback(myIPCallback);

    for (pcap_if_t* it = pcap_it; it; it = it->next) {
        if(pool.addDevice(it->name) < 0) {
            continue;
        }
    }
    pool.StartListening();
    router.initializeTable(pool);
    startBroadcast();

    sleep(5);
    my_printf("[test_route] start SendIPPacket\n");
    in_addr src, dst;
    inet_aton("10.100.1.1", &src);
    inet_aton("10.100.2.2", &dst);
    u_char buf[14] = "hello, world!";
    sendIPPacket(pool, src, dst, IPPROTO_UDP, buf, 13);
    return 0;
}