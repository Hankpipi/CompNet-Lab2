#include "tcp.h"

std::set<int> alloc_socket;
std::map<int,int> socket_status;
std::mutex status_mutex;
std::mutex ack_mutex;
std::mutex read_mutex;
std::mutex fin_mutex;
std::condition_variable cv_read;
std::condition_variable cv_estab;
std::condition_variable cv_close;
struct BindManager bind_manager;
struct ListenManager listen_maganer;

TCPInitailizer::TCPInitailizer() {
    char* errbuf = NULL;
    pcap_if_t * pcap_it;
    if(pcap_findalldevs(&pcap_it, errbuf) < 0) {
        my_printf("findalldevs error: %s", errbuf);
        return ;
    }
    //pool define in device.cpp
    pool.setFrameReceiveCallback(myFrameReceivedCallback);
    setIPPacketReceiveCallback(myIPCallback);

    for (pcap_if_t* it = pcap_it; it; it = it->next)
        pool.addDevice(it->name);

    pool.StartListening();
    router.initializeTable(pool);
    startBroadcast();

    sleep(5);
}
struct TCPInitailizer TCPinitailizer;

int update_status(int socket, int status) {
    status_mutex.lock();
    if (socket_status.find(socket) == socket_status.end()) {
        my_printf("[CHANGE_STATUS] Socket not existed!\n");
        status_mutex.unlock();
        return -1;
    }
    socket_status[socket] = status;
    status_mutex.unlock();
    return 0;
}

void handleSYN(ConnRequest& req, sockaddr_in* addr) {
    my_printf("[HANDLE_SYN] [dst_port: %d]\n", req.port);
    tcphdr header;
    memset(&header, 0, sizeof(header));
    bind_manager.bind_list.find(req.conn_fd)->second.pair_seq = req.header.th_seq + 1;
    header.th_seq = bind_manager.bind_list.find(req.conn_fd)->second.start_seq;
    header.th_ack = req.header.th_seq + 1;
    header.th_sport = addr->sin_port;
    header.th_dport = req.port;
    header.th_flags = TH_SYN | TH_ACK;
    header.th_win = 65535;
    TCPToNet(header);
    header.th_sum = 0;
    header.th_sum = Checksum(&header, 20);
    sendIPPacket(pool, addr->sin_addr, req.ip, IPPROTO_TCP, &header, sizeof(header));
}

void handle_SYN_ACK(int socket, IPpacket& pkt, tcphdr& req_header) {
    if (socket_status.find(socket)->second != SYN_SENT) {
        my_printf("[handle SYN_ACK recv INFO]\033[0m My status is not SYN_SENT and recv a SYN/ACK, it will be ignored!\n");
        return ;
    }
    update_status(socket, ESTAB);
    tcphdr header;
    memset(&header, 0, sizeof(header));
    header.th_seq = req_header.th_ack;
    header.th_ack = req_header.th_seq + 1;
    header.th_dport = req_header.th_sport;
    header.th_sport = req_header.th_dport;
    header.th_flags = TH_ACK;
    header.th_win = 65535;
    TCPToNet(header);
    header.th_sum = 0;
    header.th_sum = Checksum(&header, 20);
    sendIPPacket(pool, pkt.header.ip_dst, pkt.header.ip_src, IPPROTO_TCP, &header, sizeof(header));
    bind_manager.bind_list.find(socket)->second.pair_addr.sin_addr.s_addr = pkt.header.ip_src.s_addr;
    bind_manager.bind_list.find(socket)->second.pair_addr.sin_port = req_header.th_sport;
}

void sendSYN(int socket, sockaddr_in src_addr_in, const sockaddr* dst_addr) {
    tcphdr header;
    memset(&header, 0, sizeof(header));
    header.th_seq = bind_manager.bind_list.find(socket)->second.start_seq;
    header.th_sport = src_addr_in.sin_port;
    header.th_dport = ((sockaddr_in*)dst_addr)->sin_port;
    header.th_flags = TH_SYN;
    header.th_win = 65535;
    TCPToNet(header);
    header.th_sum = 0;
    header.th_sum = Checksum(&header, 20);
    sendIPPacket(pool, src_addr_in.sin_addr, ((sockaddr_in*)dst_addr)->sin_addr, IPPROTO_TCP, &header, sizeof(header));
}

void sendFIN(int socket) {
    SocketInfo& socket_info = bind_manager.bind_list.find(socket)->second;
    tcphdr header;
    memset(&header, 0, sizeof(header));
    header.th_seq = socket_info.seq;
    header.th_ack = socket_info.pair_seq;
    header.th_sport = socket_info.addr.sin_port;
    header.th_dport = socket_info.pair_addr.sin_port;
    header.th_flags = TH_FIN;
    header.th_win = 65535;
    TCPToNet(header);
    header.th_sum = 0;
    header.th_sum = Checksum(&header, sizeof(header));
    sendIPPacket(pool, socket_info.addr.sin_addr, socket_info.pair_addr.sin_addr, IPPROTO_TCP, &header, sizeof(header));
}

void send_FINACK(int fd) {
    SocketInfo socket_info = bind_manager.bind_list.find(fd)->second;
    tcphdr header;
    memset(&header, 0, sizeof(header));
    header.th_seq = socket_info.seq;
    header.th_ack = socket_info.pair_seq;
    header.th_sport = socket_info.addr.sin_port;
    header.th_dport = socket_info.pair_addr.sin_port;
    header.th_flags = TH_FIN | TH_ACK;
    header.th_win = 65535;
    TCPToNet(header);
    header.th_sum = 0;
    header.th_sum = Checksum(&header, sizeof(header));
    sendIPPacket(pool, socket_info.addr.sin_addr, socket_info.pair_addr.sin_addr, IPPROTO_TCP, &header, sizeof(header));
}

int sendWrite(int fildes, size_t nbyte, const void* buf) {
    tcphdr header;
    size_t header_len = sizeof(header);
    memset(&header, 0, header_len);
    u_char packet[header_len + nbyte];
    auto& socket_info = bind_manager.bind_list.find(fildes)->second;
    socket_info.last_len = nbyte;
    header.th_seq = socket_info.seq;
    header.th_ack = socket_info.pair_seq;
    header.th_sport = socket_info.addr.sin_port;
    header.th_dport = socket_info.pair_addr.sin_port;
    header.th_win = 65535;
    TCPToNet(header);
    header.th_sum = 0;
    header.th_sum = Checksum(&header, header_len);
    memcpy(packet, &header, header_len);
    memcpy(packet + header_len, buf, nbyte);
    sendIPPacket(pool, socket_info.addr.sin_addr, socket_info.pair_addr.sin_addr, IPPROTO_TCP, &packet, sizeof(packet));
    return 0;
}

void freeSocket(int socket) {
    bind_manager.bind_list.erase(bind_manager.bind_list.find(socket));    

    listen_maganer.mutex.lock();
    for (auto iter = listen_maganer.listen_items.begin(); iter != listen_maganer.listen_items.end(); ++iter) {
        if (iter->socket == socket) {
            listen_maganer.listen_items.erase(iter);
            break;
        }
    }
    listen_maganer.mutex.unlock();

    alloc_socket.erase(alloc_socket.find(socket));
    in_port_t port = bind_manager.bind_list.find(socket)->second.addr.sin_port;
    in_addr ip = bind_manager.bind_list.find(socket)->second.addr.sin_addr;

    Device* dev = pool.findDevice(ip);
    dev->mutex_port.lock();
    dev->free_port[port] = 1;
    dev->mutex_port.unlock();

    status_mutex.lock();
    socket_status.erase(socket_status.find(socket));
    status_mutex.unlock();
}

int TCP_handler(IPpacket& pkt, int len) {
    tcphdr header = *(tcphdr*)(pkt.payload);
    if (Checksum(&header, sizeof(header)) != 0) {
        my_printf("[TCP Handler] Checksum error\n");
        return -1;
    }
    my_printf("[TCP Handler] Checksum success\n");
    TCPToHost(header);
    in_addr ip = pkt.header.ip_dst;
    in_addr pair_ip = pkt.header.ip_src;
    in_port_t port = header.th_dport;
    in_port_t pair_port = header.th_sport;
    my_printf("[TCP Handler] packet from ip=%s port=%d flags=%d \n",
                    IPtoStr(pair_ip), pair_port, header.th_flags);
    Device* dev = pool.findDevice(ip);
    if (dev == NULL) {
        my_printf("[TCP Handler] Error: IP don't exist in this host!\n");
        return -1;
    }
    sockaddr_in sock, another_sock;
    sock.sin_addr = ip;
    sock.sin_port = port;
    another_sock.sin_addr = pair_ip;
    another_sock.sin_port = pair_port;
    int socket = -1;
    for (auto& item : bind_manager.bind_list) {
        if (((item.second.addr.sin_addr.s_addr == sock.sin_addr.s_addr && item.second.addr.sin_port == sock.sin_port)
            || (item.second.pair_addr.sin_addr.s_addr == another_sock.sin_addr.s_addr && item.second.pair_addr.sin_port == another_sock.sin_port))
            && !item.second.is_listening) {
                socket = item.first;
                break;
            }
    }
    if (check_SYN(header)) {
        listen_maganer.mutex.lock();
        for (auto& item : listen_maganer.listen_items) {
            if (item.sockaddr->sin_addr.s_addr == pkt.header.ip_dst.s_addr && (item.sockaddr->sin_port == header.th_dport)) {
                item.requests.push_back(ConnRequest(-1, pkt.header.ip_src, pair_port, header));
                listen_maganer.mutex.unlock();
                return 0;
            }
        }
        listen_maganer.mutex.unlock();
        my_printf("[TCP Handler] Drop SYN packet: target ip is not listening\n");
        return -1;
    }
    if(socket < 0) {
        my_printf("[TCP Handler] Error: socket not find!\n");
        return -1;
    }
    statusForward(socket, pkt, len, header);
    return 0;
}

int statusForward(int socket, IPpacket& pkt, int len, tcphdr& header) {
    int status = socket_status.find(socket)->second;
    std::unique_lock<std::mutex> lk(ack_mutex);
    if (check_SYN_ACK(header)) {
        handle_SYN_ACK(socket, pkt, header);
        lk.unlock();
        cv_estab.notify_all();
        return 0;
    }
    if (check_ACK(header)) {
        if (check_FIN(header)) {
            if (status == CLOSING) {
                status = TIME_WAIT;
            } else if (status == FIN_WAIT_1)
                status = FIN_WAIT_2;
            cv_close.notify_all();
            return 0;
        }
        if (status == SYN_RCVD) {
            bind_manager.bind_list.find(socket)->second.pair_addr.sin_addr.s_addr = pkt.header.ip_src.s_addr;
            bind_manager.bind_list.find(socket)->second.pair_addr.sin_port = header.th_sport;
            update_status(socket, ESTAB);
            lk.unlock();
            cv_estab.notify_all();
            return 0;
        }
        if ((int)header.th_ack != bind_manager.bind_list.find(socket)->second.seq + bind_manager.bind_list.find(socket)->second.last_len) {
            my_printf("[statusForward] ACK Error!\n");
            return -1;
        }
        bind_manager.bind_list.find(socket)->second.seq += bind_manager.bind_list.find(socket)->second.last_len;
        lk.unlock();
        cv_estab.notify_all();
        return 0;

    } 
    if (check_FIN(header)) {
        bind_manager.bind_list.find(socket)->second.pair_seq += 1;
        send_FINACK(socket);
        if (status == ESTAB) {
            status = CLOSE_WAIT;
        } else if (status == FIN_WAIT_2) {
            status = TIME_WAIT;
            lk.unlock();
            cv_close.notify_all();
        } else if (status == FIN_WAIT_1) {
            status = CLOSING;
            cv_close.notify_all();
        }
        return 0;
    }
    if (status == ESTAB || status == FIN_WAIT_1) {
        std::unique_lock<std::mutex> lk(read_mutex);
        size_t ip_header_len = sizeof(ip);
        u_char* content = (u_char*)pkt.payload + ip_header_len;
        auto& socket_info = bind_manager.bind_list.find(socket)->second;
        for (int i = 0; i < len - (int)ip_header_len; ++i) {
            socket_info.buffer.push_back(content[i]);
        }
        lk.unlock();
        cv_read.notify_all();
        return 0;
    }
    return -1;
}
extern "C" {
int __real_socket(int domain, int type, int protocol);
int __wrap_socket(int domain, int type, int protocol) {
    if (domain == PF_INET && type == SOCK_STREAM) {
        for(int i = SOCKET_MIN; i < SOCKET_MAX; ++i) {
            if (alloc_socket.find(i) != alloc_socket.end())
                continue;
            status_mutex.lock();
            socket_status[i] = CLOSED;
            status_mutex.unlock();
            alloc_socket.insert(i);
            bind_manager.bind_list[i] = SocketInfo();
            return i;
        }
    }
    return -1;
}

int __real_bind(int socket, const struct sockaddr* address, socklen_t address_len);
int __wrap_bind(int socket, const struct sockaddr* address, socklen_t address_len) {
    in_addr ip;
    in_port_t port;
    sockaddr_in* addr = (sockaddr_in*)address;
    ip.s_addr = addr->sin_addr.s_addr;
    port = addr->sin_port;
    auto dev = pool.findDevice(ip);
    if (dev == NULL) {
        my_printf("[BIND]: IP address is invalid\n");
        return -1;
    }
    dev->mutex_port.lock();
    if (!dev->free_port[port]) {
        my_printf("[BIND]: Port is occupied\n");
        dev->mutex_port.unlock();
        return -1;
    }
    if (port == 0) {
        for (int i = 1024; i <= 65536; ++i)
            if (dev->free_port[i]) {
                port = i;
                break;
            }
    }
    dev->free_port[port] = 0;
    dev->mutex_port.unlock();
    bind_manager.bind_list[socket] = SocketInfo();
    bind_manager.bind_list[socket].addr.sin_port = port;
    if (ip.s_addr == INADDR_ANY)
        bind_manager.bind_list[socket].addr.sin_addr.s_addr = dev->ip.s_addr;
    else
        bind_manager.bind_list[socket].addr.sin_addr.s_addr = ip.s_addr;
    return 0;
}

int __real_listen(int socket, int backlog);
int __wrap_listen(int socket, int backlog) {
    try {
        if (bind_manager.bind_list.find(socket) == bind_manager.bind_list.end()) {
            my_printf("[LISTEN]: Socket not allocated\n");
            return -1;
        }
        bind_manager.bind_list[socket].is_listening = 1;
        sockaddr_in& sockaddr = bind_manager.bind_list[socket].addr;
        if (sockaddr.sin_port == 0) {
            my_printf("[LISTEN]: Socket information is not compeleted\n");
            return -1;
        }
        listen_maganer.mutex.lock();
        status_mutex.lock();
        listen_maganer.listen_items.push_back(ListenItem(socket, &sockaddr));
        socket_status[socket] = LISTEN;
        status_mutex.unlock();
        listen_maganer.mutex.unlock();
        my_printf("[LISTEN] Socket %d start listening", socket);
    } catch (const char* err) {
        my_printf("[LISTEN] Error: %s\n", err);
        return -1;
    }
    return 0;
}

int __real_accept(int socket, struct sockaddr* address, socklen_t* address_len);
int __wrap_accept(int socket, struct sockaddr* address, socklen_t* address_len) {
    for (auto& item : listen_maganer.listen_items) {
        if (socket != item.socket)
            continue;
        while (1) {
            listen_maganer.mutex.lock();
            if (item.requests.size() == 0) {
                listen_maganer.mutex.unlock();
                continue;
            } else {
                ConnRequest req = item.requests[0];
                req.conn_fd = __wrap_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
                bind_manager.bind_list[req.conn_fd] = SocketInfo();
                bind_manager.bind_list[req.conn_fd].pair_addr.sin_family = AF_INET;
                bind_manager.bind_list[req.conn_fd].pair_addr.sin_addr.s_addr = req.ip.s_addr;
                bind_manager.bind_list[req.conn_fd].pair_addr.sin_port = req.port;
                bind_manager.bind_list[req.conn_fd].addr = bind_manager.bind_list[socket].addr;
                update_status(req.conn_fd, SYN_RCVD);
                item.requests.erase(item.requests.begin());
                listen_maganer.mutex.unlock();
                std::unique_lock<std::mutex> lk(ack_mutex);
                while (1) {
                    handleSYN(req, item.sockaddr);
                    if (cv_estab.wait_for(lk, std::chrono::seconds(1), [&] { return socket_status.find(req.conn_fd)->second == ESTAB;})) {
                        my_printf("[ACCEPT] Accept successfully!\n");
                        break;
                    }
                }
                if (address != NULL) {
                    memcpy(address, &bind_manager.bind_list[req.conn_fd].addr, sizeof(sockaddr_in));
                    *address_len = sizeof(sockaddr_in);
                }
                return 0;
            }
        }
    }
    my_printf("[ACCEPT] Error: socket %d is not listening! \n", socket);
    return -1;
}

int __real_connect(int socket, const struct sockaddr* address, socklen_t address_len);
int __wrap_connect(int socket, const struct sockaddr* address, socklen_t address_len) {
    if(bind_manager.bind_list.find(socket) == bind_manager.bind_list.end()) {
        my_printf("[CONNECT] Socket %d has not bind\n", socket);
        return -1;
    }
    in_addr target_ip = ((sockaddr_in*)address)->sin_addr;
    sockaddr_in src_addr_in = bind_manager.bind_list.find(socket)->second.addr;
    if (src_addr_in.sin_addr.s_addr == 0) {
        for (auto& item : router.routetable) {
            if (item.contain_ip(target_ip)) {
                src_addr_in.sin_addr.s_addr = item.dev->ip.s_addr;
                break;
            }
        }
        if (src_addr_in.sin_addr.s_addr == 0) {
            my_printf("[CONNECT] Error: Target IP isn't in route table!\n");
            return -1;
        }
    }
    Device* dev = pool.findDevice(src_addr_in.sin_addr);
    if (dev == NULL) {
        my_printf("[CONNECT] Error: IP address!\n");
        return -1;
    }
    if (src_addr_in.sin_port == 0) {
        dev->mutex_port.lock();
        for (int port = 1024; port <= 65536; ++port) {
            if (dev->free_port[port]) {
                src_addr_in.sin_port = port;
                break;
            }
        }
        dev->free_port[src_addr_in.sin_port] = 0;
        dev->mutex_port.unlock();
    }
    sendSYN(socket, src_addr_in, address);
    bind_manager.bind_list[socket].addr = src_addr_in;
    update_status(socket, SYN_SENT);
    std::unique_lock<std::mutex> lk(ack_mutex);
    while (1) {
        if (cv_estab.wait_for(lk, std::chrono::seconds(1), [&] { return socket_status.find(socket)->second == ESTAB; })) {
            my_printf("[CONNECT] CONNECT successfully!\n");
            break;
        } else {
            my_printf("[CONNECT] Timeout resend\n");
            sendSYN(socket, src_addr_in, address);
            continue;
        }
    }
    return 0;
}

ssize_t __real_write(int fildes, const void* buf, size_t nbyte);
ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte) {
    if (socket_status.find(fildes)->second != ESTAB) {
        my_printf("[WRITE] Error: Connection has not been estabished!\n");
        return 0;
    }
    SocketInfo& socket_info = bind_manager.bind_list.find(fildes)->second;
    sendWrite(fildes, nbyte, buf);
    socket_info.waiting_ack = 1;
    std::unique_lock<std::mutex> lk(ack_mutex);
    int retry = 0;
    while (1) {
        if (cv_estab.wait_for(lk, std::chrono::seconds(3), [&] { return !socket_info.waiting_ack; })) {
            my_printf("[WRITE] Done!\n");
            break;
        }
        sendWrite(fildes, nbyte, buf);
        retry += 1;
        my_printf("[WRITE] sendWrite retry time %d\n", retry);
        if (retry >= MAX_TCP_RETRY_NUM) {
            lk.unlock();
            my_printf("[WRITE] Error: Write failed\n");
            return 0;
        }
    }
    return nbyte;
}

ssize_t __real_read(int fildes, void* buf, size_t nbyte);
ssize_t __wrap_read(int fildes, void* buf, size_t nbyte) {
    auto pr = bind_manager.bind_list.find(fildes);
    if (pr != bind_manager.bind_list.end()) {
        my_printf("[READ] Error: Connection has not been estabished!\n");
        return 0;
    }
    SocketInfo& socket_info = pr->second;
    std::unique_lock<std::mutex> lk(read_mutex);
    cv_read.wait(lk, [&] { return socket_info.buffer.size() >= nbyte; });
    for (int i = 0; i < (int)nbyte; ++i) {
        ((u_char*)buf)[i] = socket_info.buffer[0];
        socket_info.buffer.erase(socket_info.buffer.begin());
    }
    return nbyte;
}

int __real_close(int fildes);
int __wrap_close(int fildes) {
    if (bind_manager.bind_list.find(fildes) == bind_manager.bind_list.end()) {
        my_printf("[CLOSE] Error: Connection has not been estabished!\n");
        return 0;
    }
    if(socket_status.find(fildes)->second == ESTAB)
        update_status(fildes, FIN_WAIT_1);
    sendFIN(fildes);
    std::unique_lock<std::mutex> lk(fin_mutex);
    for (int i = 0; i < MAX_TCP_RETRY_NUM; ++i) {
        if (cv_close.wait_for(lk, std::chrono::seconds(1), [&] { 
            return socket_status.find(fildes)->second == FIN_WAIT_2 || socket_status.find(fildes)->second == CLOSING; })) {
            break;
        }
        sendFIN(fildes);
    }
    cv_close.wait(lk, [&] { return socket_status.find(fildes)->second == TIME_WAIT; });
    std::this_thread::sleep_for(std::chrono::seconds(2));
    freeSocket(fildes);
    return 0;
}

int __real_getaddrinfo(const char* node, const char* service,
    const struct addrinfo* hints, struct addrinfo** res);
int __wrap_getaddrinfo(const char* node, const char* service,
    const struct addrinfo* hints, struct addrinfo** res) {
    // if (hints->ai_family == AF_INET && hints->ai_protocol == IPPROTO_TCP && hints->ai_socktype == SOCK_STREAM) {
    //     addrinfo* head = new addrinfo;
    //     *res = head;
    //     head->ai_next = NULL;
    //     sockaddr_in* tmp = new sockaddr_in;
    //     inet_pton(AF_INET, node, &tmp->sin_addr.s_addr);
    //     tmp->sin_addr.s_addr = htonl(tmp->sin_addr.s_addr);
    //     tmp->sin_port = htons(atoi(service));
    //     head->ai_addr = (sockaddr*)(tmp);
    //     head->ai_addrlen = sizeof(sockaddr_in);
    //     return 0;
    // }
    return -1;
}
}
