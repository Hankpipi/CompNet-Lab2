#include "route.h"

Router router;
std::mutex table_mutex;

RouterItem::RouterItem(const in_addr& _ip_prefix, const in_addr& _subnetMask, Device* _dev, const u_char* _next_hop, const int _dist)
    : dev(_dev) ,next_hop((u_char *)_next_hop), dist(_dist) {
    entry_time = time(NULL);
    ip_prefix.s_addr = _ip_prefix.s_addr;
    subnetMask.s_addr = _subnetMask.s_addr;
};

bool RouterItem::contain_ip(const in_addr& dst_ip) const {
    return ((dst_ip.s_addr & subnetMask.s_addr) == ip_prefix.s_addr);
}

bool RouterItem::operator < (const RouterItem& item) const {
    if (subnetMask.s_addr != item.subnetMask.s_addr)
        return subnetMask.s_addr > item.subnetMask.s_addr;
    return ip_prefix.s_addr < item.ip_prefix.s_addr;
}

Router::~Router() { 
    t.join(); 
}

void UpdateTalble() {
    while (1) {
        table_mutex.lock();
        router.printTable();
        router.InsertLocalIP(pool);
        router.check();
        table_mutex.unlock();
        sleep(CHECK_GAP_TIME);
    }
}

void Router::printTable() {
    printf("[Print Routing Table]\n");
    printf("\033[34m[Table]\033[0m\n");
    printf("_____________________________________________________________________________________________________\n");
    printf("||%18s||%18s||%18s||%18s||%18s||\n", "ip_prefix", "subnetMask", "send_by", "next_hop", "dist");
    for (auto& item : routetable) {
        printf("||%18s||%18s||%18s||%18s||%18d||\n", IPtoStr(item.ip_prefix), IPtoStr(item.subnetMask),
            item.dev->mac, item.next_hop, item.dist);
    }
    printf("=====================================================================================================\n"); 
}

void Router::check() {
    for (auto it = routetable.begin(); it != routetable.end(); ++it)
        if (time(NULL) - it->entry_time >= ROUTER_REMAIN_TIME)
            routetable.erase(it);
}

void Router::InsertLocalIP(DevicePool& pool) {
    printf("[InsertLocalIP]......\n");
    for (auto& dev : pool.device_list) {
        in_addr tmp_ip_prefix, tmp_mask;
        tmp_ip_prefix.s_addr = dev->ip.s_addr & dev->subnetMask.s_addr;
        tmp_mask.s_addr = dev->subnetMask.s_addr;
        this->InsertTable(tmp_ip_prefix, tmp_mask, (u_char*)"00:00:00:00:00:00", dev, 0);
    }
}

void Router::initializeTable(DevicePool& pool) {
    printf("[initializeTable]\n");
    this->InsertLocalIP(pool);
    t = std::thread(UpdateTalble);
}

u_char* Router::GetNexthop(const in_addr& dstIP) {
    for (auto& item : routetable) {
        if (item.contain_ip(dstIP)) {
            return item.next_hop;
        }
    }
    throw "target IP not found in route table!";
}

void broadcastRouteTable(const Device* dev) {
    while (1) {
        table_mutex.lock();
        printf("[broadcastRouteTable Function]: ...\n");
        int size = router.routetable.size();
        int packet_size = sizeof(TablePacket);
        int total_size = size * packet_size;
        printf("[broadcastRouteTable Function] [table_size: %d]\n", size);
        u_char content[total_size];
        auto it = router.routetable.begin();
        for (int i = 0; i < size; ++i, ++it) {
            TablePacket tmp_pkt;
            tmp_pkt.dist = it->dist;
            tmp_pkt.ip_prefix.s_addr = it->ip_prefix.s_addr;
            tmp_pkt.subnetMask.s_addr = it->subnetMask.s_addr;
            StrToMac((const u_char*)it->next_hop, tmp_pkt.next_mac);
            memcpy((u_char*)(content + i * packet_size), (u_char*)&tmp_pkt, packet_size);
        }
        dev->sendFrame((void*)content, total_size, ROUTE_PROTO, "ff:ff:ff:ff:ff:ff");
        table_mutex.unlock();
        sleep(1);
    }
}

void Router::InsertTable(const in_addr ip_prefix, const in_addr mask,
    const u_char* nextHop, Device* dev, const int dist) {
    if(dist >= 10) {
        printf("[InsertTable] drop RouteItem whose dist >= 10\n");
        return ;
    }
    bool is_find = 0;
    for (auto it = routetable.begin(); it != routetable.end(); ++it) {
        if (it->ip_prefix.s_addr == ip_prefix.s_addr && it->subnetMask.s_addr == mask.s_addr) {
            is_find = 1;
            if (it->dist >= dist) {
                routetable.erase(it);
                routetable.insert(RouterItem(ip_prefix, mask, dev, nextHop, dist));
                printf("[handleReceiveRouteTable] Insert [ip_prefix=%s] [mask=%s]\n", 
                        IPtoStr(ip_prefix), IPtoStr(mask));
                break;
            }
        }
    }
    if (!is_find) {
        routetable.insert(RouterItem(ip_prefix, mask, dev, nextHop, dist));
        printf("[handleReceiveRouteTable] Insert [ip_prefix=%s] [mask=%s]\n", 
                IPtoStr(ip_prefix), IPtoStr(mask));
    }
}

void Router::handleReceiveRouteTable(const u_char* srcMac, const u_char* content, const int len, Device* dev) {
    printf("[handleReceiveRouteTable] Start\n");
    assert(len % sizeof(TablePacket) == 0);
    int single_size = sizeof(TablePacket);
    int cnt = len / single_size;
    TablePacket neighbor_table[cnt];
    for (int i = 0; i < cnt; ++i) {
        memcpy(neighbor_table + i, content + single_size * i, single_size);
        ++neighbor_table[i].dist;
    }
    table_mutex.lock();
    for (int i = 0; i < cnt; ++i) {
        this->InsertTable(neighbor_table[i].ip_prefix, neighbor_table[i].subnetMask, 
                            srcMac, dev, neighbor_table[i].dist);
    }
    table_mutex.unlock();
    printf("[handleReceiveRouteTable] Done\n");
}

Device* DevicePool::findDevice(in_addr src, in_addr dst) {
    for (auto& dev : device_list) {
        if (dev->ip.s_addr == src.s_addr) {
            return dev;
        }
    }
    for (auto& item : router.routetable) {
        if ((dst.s_addr & item.subnetMask.s_addr) == item.ip_prefix.s_addr) {
            return item.dev;
        }
    }
    return NULL;
}