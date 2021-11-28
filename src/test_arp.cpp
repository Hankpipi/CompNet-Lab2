#include "arp.h"
#include "packetio.h"
#include "ip.h"

int main() {

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