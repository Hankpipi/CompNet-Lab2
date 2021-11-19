#include "packetio.h"
#include "ip.h"

int main() {
    char* errbuf = NULL;
    pcap_if_t * pcap_it;
    if(pcap_findalldevs(&pcap_it, errbuf) < 0) {
        printf("findalldevs error: %s", errbuf);
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
    return 0;
}