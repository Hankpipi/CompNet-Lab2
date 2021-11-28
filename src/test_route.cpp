#include "packetio.h"
#include "ip.h"
#include "route.h"

int main() {
    printf("[test_route] start SendIPPacket\n");
    in_addr src, dst;
    inet_aton("10.100.1.1", &src);
    inet_aton("10.100.2.2", &dst);
    u_char buf[14] = "hello, world!";
    sendIPPacket(pool, src, dst, IPPROTO_UDP, buf, 13);
    return 0;
}