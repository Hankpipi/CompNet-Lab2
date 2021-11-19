#ifndef ROUTETABLE_H_
#define ROUTETABLE_H_
#include "device.h"

extern std::mutex table_mutex;
struct TablePacket {
    struct __attribute__((__packed__)) {
        in_addr ip_prefix;
        in_addr subnetMask;
        u_char next_mac[6];
        int dist;
    };
};
struct RouterItem {
    in_addr ip_prefix;
    in_addr subnetMask;
    Device* dev;
    u_char* next_hop;
    time_t entry_time;
    int dist;
    RouterItem(const in_addr& _ip_prefix, const in_addr& _subnetMask, Device* _dev, const u_char* _next_hop, const int _dist);
    bool contain_ip(const in_addr& dst_ip) const;
    bool operator < (const RouterItem& item) const;
};
struct Router {
    std::set<RouterItem> routetable;
    u_char* GetNexthop(const in_addr& dstIP);
    std::thread t;
    void InsertTable(const in_addr ip_prefix, const in_addr mask, const u_char* nextHop, Device* device, const int dist);
    void handleReceiveRouteTable(const u_char* srcMac, const u_char* content, const int len, Device* dev);
    void check();
    void reset();
    void printTable();
    void deleteTableItem(const u_char* mac);
    void initializeTable(DevicePool& DevicePool);
    void InsertLocalIP(DevicePool& pool);
    ~Router();
};
void broadcastRouteTable(const Device* dev);
extern Router router;
#endif
