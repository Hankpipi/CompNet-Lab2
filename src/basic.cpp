#include "basic.h"

void StrToMac(const u_char* mac, u_char* dst) {
    int tmp[6];
    sscanf((char*)mac, "%02X:%02X:%02X:%02X:%02X:%02X", 
            tmp, tmp + 1, tmp + 2, 
            tmp + 3, tmp + 4, tmp + 5);
    for (int i = 0; i < ETHER_ADDR_LEN; ++i) {
        dst[i] = (u_char)tmp[i];
    }
}
u_char* MacToStr(const u_char* str) {
    char* ret = new char[18];
    sprintf(ret, "%02x:%02x:%02x:%02x:%02x:%02x",
        str[0],str[1],str[2],
        str[3],str[4],str[5]);
    return (u_char*)ret;
}

char* IPtoStr(in_addr IP) {
    char* ip = new char[20];
    snprintf(ip, 20, "%d.%d.%d.%d", IP.s_addr & 255, (IP.s_addr >> 8) & 255, (IP.s_addr >> 16) & 255, IP.s_addr >> 24);
    return ip;
}

u_char* GetMACAddr(const char* name) {
    #ifndef __APPLE__
    struct ifreq ifreq;
    int sock;
    char* mac = new char[18];
    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return NULL;
    }
    strcpy(ifreq.ifr_name, name);
    if (ioctl(sock, SIOCGIFHWADDR, &ifreq) < 0) {
        perror("ioctl");
        return NULL;
    }
    sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
        (u_char)ifreq.ifr_hwaddr.sa_data[0],
        (u_char)ifreq.ifr_hwaddr.sa_data[1],
        (u_char)ifreq.ifr_hwaddr.sa_data[2],
        (u_char)ifreq.ifr_hwaddr.sa_data[3],
        (u_char)ifreq.ifr_hwaddr.sa_data[4],
        (u_char)ifreq.ifr_hwaddr.sa_data[5]);
    return (u_char*)mac;
    #else
    char* errbuf = NULL;
    pcap_if_t * pcap_it;
    u_char* ret = NULL;
    if(pcap_findalldevs(&pcap_it, errbuf) < 0) {
        printf("findalldevs error: %s", errbuf);
        return NULL;
    }
    for (; pcap_it; pcap_it = pcap_it ->next) {
        if(strcmp(pcap_it -> name, name) == 0) {
            for (pcap_addr_t* a = pcap_it -> addresses; a; a = a->next) {
                if(a->addr->sa_family == AF_LINK) {
                    struct sockaddr_dl* link = (struct sockaddr_dl*)a->addr->sa_data;

                    u_char mac[link->sdl_alen];
                    memcpy(mac, LLADDR(link), link->sdl_alen);

                    if(link->sdl_alen == 6){
                        ret = MacToStr(mac);
                        // sprintf(ret, "%02x:%02x:%02x:%02x:%02x:%02x",
                        //             (unsigned char)mac[0],(unsigned char)mac[1],
                        //             (unsigned char)mac[2],(unsigned char)mac[3],
                        //             (unsigned char)mac[4],(unsigned char)mac[5]);
                    } else if(link->sdl_alen > 6) {
                        ret = MacToStr(mac + 1);
                        // sprintf(ret, "%02x:%02x:%02x:%02x:%02x:%02x",
                        //             (unsigned char)mac[1],(unsigned char)mac[2],
                        //             (unsigned char)mac[3],(unsigned char)mac[4],
                        //             (unsigned char)mac[5],(unsigned char)mac[6]);
                    }
                    return ret;
                }
            }
        }
    }
    return NULL;
    #endif
}

int GetIPInfo(const char* dev_name, in_addr& dev_ip, in_addr& subnetMask) {
    ifaddrs* if_link;
    if (getifaddrs(&if_link) < 0) {
        throw "getifaddr failed!";
        return -1;
    }
    dev_ip.s_addr = 0;
    subnetMask.s_addr = 0;
    ifaddrs* tmp = if_link;
    while (tmp) {
        if (strcmp(tmp->ifa_name, dev_name) == 0 && tmp->ifa_addr->sa_family == AF_INET) {
            sockaddr_in* tmp_addr = (sockaddr_in*)(tmp->ifa_addr);
            dev_ip = tmp_addr->sin_addr;
            tmp_addr = (sockaddr_in*)(tmp->ifa_netmask);
            subnetMask = tmp_addr->sin_addr;
            char tmp_ip[30], tmp_mask[30];
            strcpy(tmp_ip, inet_ntoa(dev_ip));
            strcpy(tmp_mask, inet_ntoa(subnetMask));
            printf("[GetIPInfo] The IP address of %s is %s, subnetMask is %s\n", dev_name, IPtoStr(dev_ip), IPtoStr(subnetMask));
            break;
        }
        tmp = tmp->ifa_next;
    }
    if (dev_ip.s_addr == 0) {
        printf("[GetIPInfo] Device %s have no IP\n", dev_name);
        return -1;
    }
    return 0;
}

bool cmp_ip::operator()(in_addr ip1, in_addr ip2) const {
    return ip1.s_addr < ip2.s_addr;
}

bool cmp_str:: operator()(const u_char *a, const u_char *b) const {
    return std::strcmp((char*)a, (char*)b) < 0;
}

bool IsSameSubnet(in_addr ip1, in_addr ip2, in_addr SubnetMask) {
    return ((ip1.s_addr & SubnetMask.s_addr) == (ip2.s_addr & SubnetMask.s_addr));
}
