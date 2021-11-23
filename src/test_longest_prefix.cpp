#include "route.h"

int main() {
    in_addr ip_prefix_1, ip_prefix_2, subnetmask_1, subnetmask_2;
    inet_aton("10.100.1.1", &ip_prefix_1);
    inet_aton("10.100.1.1", &ip_prefix_2);
    inet_aton("255.255.0.0", &subnetmask_1);
    inet_aton("255.255.255.0", &subnetmask_2);
    ip_prefix_1.s_addr &= subnetmask_1.s_addr;
    ip_prefix_2.s_addr &= subnetmask_2.s_addr;
    Device a;
    a.mac = (u_char*)"aa:aa:aa:aa:aa:aa";
    router.routetable.insert(RouterItem(ip_prefix_1, subnetmask_1, &a, (u_char*)"a", 2));
    router.routetable.insert(RouterItem(ip_prefix_2, subnetmask_2, &a, (u_char*)"b", 2));
    router.printTable();
    in_addr ip_prefix;
    inet_aton("10.100.1.1", &ip_prefix);
    u_char* res = router.GetNexthop(ip_prefix);
    my_printf("The next hop of [%s] is [%s]\n", IPtoStr(ip_prefix), res);
    return 0;
}