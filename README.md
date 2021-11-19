# Lab2 Report

Name：喻梓浩

Student ID：1900013082

## PartA

The test code is in parta_checkpoints.cpp which correspond to checkpoint 1,2.

Input these to test.

```bash
cd src
make clean
make parta
./parta
```



### checkpoint1

By running device_activate_test() in parta_checkpoints.cpp, which print all the device information on the host, showing the result:

![image-20211025183551213](/Users/bytedance/Library/Application Support/typora-user-images/image-20211025183551213.png)



### checkpoint2

#### send

We send frame through device "en0" whose mac address is 3c:22:fb:c6:60:22， the destmac address is 82:9b:28:20:c8:01.

![image-20211025184834458](/Users/bytedance/Library/Application Support/typora-user-images/image-20211025184834458.png)

By monitor device "en0" by Wireshark, we can find the frame we send.

![image-20211025185059256](/Users/bytedance/Library/Application Support/typora-user-images/image-20211025185059256.png)



#### Receive

After receving thread of "en0" start listening , we visit some websites by Google Chrome, we can see that "en0" successfully receive frames from web service.

![image-20211025191210986](/Users/bytedance/Library/Application Support/typora-user-images/image-20211025191210986.png)



## PartB

### Working environment

MacOS does not support vnet，try to build linux environment by docker

```bash
docker build -t lab2-env .
docker run -it --privileged=true -v $(pwd):/home/Lab2 lab2-env
```



### Writing Task 1

1. When target IP and source IP are in same subnet, I broadcast a packet(like arp protocol) to all the subnet to find the MAC address of target IP, and record it's MAC address by an arp-map.
2. When target IP and source IP are not in same subnet, I use routing table to find the next hop to the target IP. Routing table is obtained by my own routing algorithm.

### Writing Task 2

1. Every node have a thread to broadcast it's routing table, and a thread to update it's routing table.
2. Each item in routing table records the ip_prefix, ip_subnetMast, device to send this packet, MAC address of next-hop, distance from the target IP address and the time it entry to the table.
3. When a router receiving a routing table from it's neighborhood,  the router will merge these two tables: 
   1. When the item is not exist in table, add the item to table directly.
   2. When the item is exist in table, compare distance to the target IP address of them,  accept the closer one and update entry time of this item.
4. Updating thread check the entry time of each item, delete the item who is expired.



There is a situation, when the virtual network is like: ns1-ns2-ns3, they are exchanging it's routing table. When ns3 is disconnected, the information about ns3 in the routing table of ns1 and ns2 will not be deleted, because this information about ns3 will continually delivered between them, the distance to ns3 in this item will be continually increasing. So I use the strategy that deleting the item whose distance to target IP address is greater than or equal to 10.

### Checkpoint 3 

I cature my own IP packet send from 10.100.1.1 to 10.100.2.2 by tcpdump，the message to send is "hello, world!".

The first 14 bytes are frame header, including dst MAC address(62:5c:58:e3:ab :2e), src MAC address(2a:78:29:b2:e7:84) and ether_type(0800 corresponding to ETHERTYPE_IP). The next 20 bytes are ip header, including IPPROTO(4000 corresponding to IPPROTO_UDP), src IP address(0a64 0101 corresponding to 10.100.1.1), dst IP address(0a64 0202  corresponding to 10.100.2.2) and checksum etc. The remaining bytes are corresponding to the message "hello, world!".

![image-20211105140251390](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105140251390.png)

The second packet I capture is the packet that contain the routing table.

The first 14 bytes are frame header, including dst MAC address(ff:ff:ff:ff:ff :ff), src MAC address(2a:78:29:b2:e7:84) and ether_type(ffff corresponding to my own routing protocol). The remaining 54 bytes are corresponding to the routing table sent by 2a:78:29:b2:e7:84. The table has 3 items, and each item is 18 bytes in size.

![image-20211105155141785](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105155141785.png)

### Checkpoint 4

```
# mynet.txt

4
1 2 10.100.1
2 3 10.100.2
3 4 10.100.3
0 3 10.100.4
```

We can reproduce the experiment by the following steps:

```bash
# in terminal 1
cd vnetUtils/examples/
bash ./makeVNet < mynet.txt  # build VNet
cd ../helper
bash ./execNS ns1 bash  # entry ns1
cd ../../src
make clean
make listen #  compile listen.cpp which only route(send routing table and forwarding)
# in terminal 2
bash ./execNS ns2 bash  # entry ns2
cd ../../src
./listen
# in terminal 3
bash ./execNS ns3 bash  # entry ns3
cd ../../src
./listen
# in terminal 4
bash ./execNS ns4 bash  # entry ns4
cd ../../src
./listen

# in terminal 1
./listen

# in terminal 2
ctrl+C
./listen # after 10s seconds
```

Initial routing table of ns1:

![image-20211105163038707](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105163038707.png)

Routing table of ns1 after disconnecting ns2 (waiting 10s can see the result):

![image-20211105163644332](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105163644332.png)

Routing table of ns1 after ns2 connected again:

![image-20211105163713741](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105163713741.png)

### Checkpoint 5

```
# mynet2.txt which correspond to the network structure

6
1 2 10.100.1
2 3 10.100.2
3 4 10.100.3
2 5 10.100.4
5 6 10.100.5
3 6 10.100.6

1 default 2
2 default 3
3 default 4
2 default 5
5 default 6
3 default 6
```

The routing tables of ns1,ns2,...,ns6 are as follows:

![image-20211105233112304](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233112304.png)

![image-20211105233132225](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233132225.png)

![image-20211105233153415](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233153415.png)

![image-20211105233202215](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233202215.png)

![image-20211105233213926](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233213926.png)

![image-20211105233225001](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233225001.png)

After disconnect ns5, the routing tables of ns1,...,ns4,ns6 are as follows:

![image-20211105233346336](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233346336.png)

![image-20211105233401684](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233401684.png)

![image-20211105233413543](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233413543.png)

![image-20211105233422581](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233422581.png)

![image-20211105233437430](/Users/bytedance/Library/Application Support/typora-user-images/image-20211105233437430.png)

We can see that the routing tables of ns3 and ns4 have not changed, and the routing tables of ns1, ns2 and ns6 have changed.



### Checkpoint 6

My routing table is sorted according to the subnet mask, and the item who has longer prefix length will be listed in front of the routing table. When looking up the routing table, search in order and return after finding a matched item, so the item with the longest prefix will be obtained first.

![image-20211106105949920](/Users/bytedance/Library/Application Support/typora-user-images/image-20211106105949920.png)

We can check its correctness through a unit test:

```bash
cd src
make prefix
./prefix
```

The test insert two items with different ip_prefix, and find the next hop of 10.100.1.1, showing the following result:

![image-20211106112618344](/Users/bytedance/Library/Application Support/typora-user-images/image-20211106112618344.png)