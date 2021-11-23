#include "device.h"
#include "arp.h"
#include "ip.h"

struct DevicePool pool;

void pcap_callback(Device* dev, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
    int id = dev->id;
    my_printf("[pcap_callback]: device id = %d receive [Caplen: %d] [Len: %d] packet\n", id, packet_header->caplen, packet_header->len);
    if (packet_header->caplen != packet_header->len) {
        my_printf("pcap_callback: data is not complete!\n\n");
        return;
    }
    size_t header_size = 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN;
    size_t size = packet_header->caplen - header_size;
    u_char* content = new u_char[size];
    ether_header* header = new ether_header();
    memcpy(header, packet_content, header_size);
    u_char* dst = MacToStr(header->ether_dhost);
    u_char* src = MacToStr(header->ether_shost);
    header->ether_type = ntohs(header->ether_type);
    my_printf("[pcap_callback][device's mac address = %s][frame's destmac = %s][frame's srcmac = %s][ether_type = %d]\n", 
            dev->mac, dst, src, header->ether_type);
    if (strcmp((char*)dst, (char*)dev->mac) != 0 && strcmp((char*)dst, "ff:ff:ff:ff:ff:ff") != 0) {
        my_printf("drop useless packet: frame's destmac address doesn't match\n\n");
        return;
    }
    if (header->ether_type == ETHERTYPE_ARP) {
        arpPacket pkt(packet_content + header_size);
        if (pkt.header.ar_op == ARPOP_REQUEST)
            handleARPRequest(dev, pkt);
        else if (pkt.header.ar_op == ARPOP_REPLY)
            handleARPReply(packet_content + header_size, size, (char*)src);
        else {
            my_printf("[pcap_callback][Unsupported arp op type]\n");
            return;
        }
    } else if (header->ether_type == ROUTE_PROTO) {
        memcpy(content, packet_content + header_size, size);
        router.handleReceiveRouteTable(src, content, size, dev);
    } else {
        memcpy(content, packet_content + header_size, size);
        dev->frameCallback(content, size, id);
    }
    puts("");
}

void Device::printDeviceInfo() {
    my_printf("[printDeviceInfo] id = %d name = %s, mac = %s\n", id, name, mac);
}

void device_loop(Device* dev) {
    int err;
    struct pcap_pkthdr* header = NULL;
    u_char* pkt_data = NULL;
    my_printf("[device_loop] %s receiving thread start listening ......\n", dev->name);
    while ((err = pcap_next_ex(dev->pcap, &header, (const u_char**)&pkt_data)) >= 0) {
        if(err == 0)continue;
        pcap_callback(dev, header, pkt_data);
    }
}

Device::Device() {}

Device::Device(int _id, const char* _name) {
    char* errbuf = NULL;
    pcap_t* _pcap = pcap_create(_name, errbuf); 
    if(_pcap == NULL) {
        my_printf("pcap create error %s\n", errbuf);
        throw "pcap_create failed!";
        return ;
    }
    // if((pcap_set_buffer_size(_pcap, 100)) != 0) {
    //     my_printf("ERROR\n");
    //     throw "pcap_set_buffer_size failed!";
    //     return ;
    //}
    if(pcap_activate(_pcap) != 0) {
        errbuf = pcap_geterr(_pcap);
        my_printf("pcap_activate error: %s\n", errbuf);
        throw "pcap_activate failed!";
        return ;
    }
    u_char* _mac = GetMACAddr(_name);
    if(_mac == NULL) {
        throw "Get mac address failed!";
        return ;
    }
    if(GetIPInfo(_name, this->ip, this->subnetMask) < 0) {
        throw "Get IP address failed!";
        return ;
    }
    for (int i = 0; i < 65536; ++i) {
        this->free_port[i] = 1;
    }
    this->mac = _mac;
    this->pcap = _pcap;
    this->id = _id;
    this->name = _name;
}

int DevicePool::addDevice(const char* dev_name) {
    try {
        int size = device_list.size();
        for (int i = 0; i < size; ++i) {
            Device* dev = device_list[i];
            if (strcmp(dev->name, dev_name) == 0) {
                return dev->id;
            }
        }
        Device* new_dev = new Device(device_list.size(), dev_name);
        new_dev->frameCallback = this->frameCallback;
        device_list.push_back(new_dev);
        my_printf("[addDevice] successfully add [%s] to device pool, [id=%d] [MAC=%s]\n", dev_name, new_dev->id, new_dev->mac);
        return new_dev->id;
    } catch (const char* err) {
        my_printf("[addDevice] %s error: %s\n", dev_name, err);
        return -1;
    }
}

Device::~Device() {
    this->t.join();
    this->broadcastRouteTable.join();
}

int DevicePool::findDevice(const char* dev_name) {
    int size = device_list.size();
    for (int i = 0; i < size; ++i) {
        Device* dev = device_list[i];
        if (dev->name == dev_name) {
            return dev->id;
        }
    }
    my_printf("Device not found device_list! \n");
    return -1;
}

Device* DevicePool::findDevice(in_addr src) {
    for (auto& dev : device_list) {
        if (dev->ip.s_addr == src.s_addr || src.s_addr == INADDR_ANY) {
            return dev;
        }
    }
    return NULL;
}

void DevicePool::StartListening() {
    int len = this->device_list.size();
    for(int i = 0; i < len; ++i) {
        Device* dev = this->device_list[i];
        dev->t = std::thread(device_loop, dev);
    }
}
