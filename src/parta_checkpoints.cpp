#include "packetio.h"

struct DevicePool pool;

// check if all the devices are able to activare
bool device_activate_test() {
    char* errbuf = NULL;
    pcap_if_t * pcap_it;
    if(pcap_findalldevs(&pcap_it, errbuf) < 0) {
        printf("findalldevs error: %s", errbuf);
        return 0;
    }
    for (pcap_if_t* it = pcap_it; it; it = it ->next) {
        pcap_t* _pcap = pcap_create(it -> name, errbuf); 
        u_char * mac = GetMACAddr(it -> name);
        if(_pcap == NULL) {
            printf("pcap create error %s\n", errbuf);
            continue;
        }
        int err = pcap_activate(_pcap);
        if(err != 0) {
            printf("pcap_activate error\n");
            continue;
        }
        printf("%s activate successfully, mac address is %s\n", it->name, mac);
    }
    pcap_freealldevs(pcap_it);
    return 1;
}

bool device_test() {
    pool.addDevice("en0");
    pool.addDevice("en1");
    int n = pool.device_list.size();
    for (int i = 0; i < n; ++i) {
        struct Device* dev = pool.device_list[i];
        // dev -> printDeviceInfo();
        int id = pool.findDevice(dev->name);
        if(dev->id != id) {
            printf("findDevice %s error\n", dev->name);
            return 0;
        }
    }
    return 1;
}

void sendframes(Device* dev1, Device* dev2) {
    for(int i = 0; i < 1; ++i) {
        if(dev1->sendFrame("hello, world!", 13, ETHERTYPE_VLAN, dev2->mac) < 0)
            return ;
    }
}
bool send_receive_test() {
    struct Device* dev1 = pool.device_list[0];
    std::thread tmp(sendframes, dev1, dev1);
    tmp.join();
    dev1->t.join();
    return 1;
}

int main() {
    pool.setFrameReceiveCallback(myFrameReceivedCallback);
    if(!device_activate_test()) {
        printf("device_activate_test failed!\n");
        return 0;
    }
    if(!device_test()) {
        printf("device_activate_test failed!\n");
        return 0;
    }
    if(!send_receive_test()) {
        printf("send_receive_test failed!\n");
    }
    return 0;
}
