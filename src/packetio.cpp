#include "packetio.h"
#include "ip.h"

int Device::sendFrame(const void* buf, int len, int ethtype, const void* destmac) const {
    if(len < 0) {
        LK_printf("error: buf length should >=0\n");
        return -1;
    }
    LK_printf("[sendFrame] start sending frame from %s to %s\n", this->mac, (char*)destmac);
    size_t header_size = 2 * ETHER_ADDR_LEN + ETHER_TYPE_LEN;
    size_t size = len + header_size;
    u_char* pkt = new u_char[size];
    ether_header* header = new ether_header();
    u_char *shost = new u_char[8];
    u_char *dhost = new u_char[8];
    StrToMac(this->mac, shost);
    StrToMac((u_char*)destmac, dhost);
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        header->ether_shost[i] = (u_int8_t)shost[i];
        header->ether_dhost[i] = (u_int8_t)dhost[i];
    }
    header->ether_type = htons(ethtype);
    if (sizeof(*header) != header_size) {
        LK_printf("[sendFrame] header message error\n");
        return -1;
    }
    memcpy(pkt, header, header_size);
    memcpy(pkt + header_size, buf, len);

    int err = pcap_sendpacket(this->pcap, (u_char*)pkt, size);
    if (err < 0) {
        char* err = pcap_geterr(this->pcap);
        printf("[sendFrame] pcap_sendpacket error %s\n", err);
        return -1;
    }
    LK_printf("[sendFrame] send frame succeeded! frame size is %d\n", (int)size);
    return 0;
}

int myFrameReceivedCallback(const void* buf, int len, int id) {
    LK_printf("[FrameReceivedCallback] of deivce%d:\n", id);
    int lim = std::min(len, 15);
    LK_printf("buf len = %d, the first %d bytes: \n", len, lim);
    for (int i = 0; i < lim; ++i)
        LK_printf("%0X ", *(u_int8_t*)((u_char*)buf + i));
    LK_printf("\n");
    IPCallback(buf, len);
    return 0;
}

int DevicePool::setFrameReceiveCallback(frameReceiveCallback callback) {
    try {
        this->frameCallback = callback;
    } catch (const char* err) {
        LK_printf("setFrameReceiveCallback error: %s \n", err);
        return -1;
    }
    return 0;
}
