CC = g++
AR = ar
OPT = -g -ggdb -mbmi -mbmi2 -O2

CFLAGS += --std=c++11 -fno-strict-aliasing -Wall -c -I. -I./include -I/Library/Developer/CommandLineTools/usr/lib/clang/12.0.0/include/ -I/Library/Developer/CommandLineTools/usr/include/ -I/Library/Developer/CommandLineTools/SDKs/MacOSX10.15.sdk/usr/include/

LDFLAGS+= -Wall -lpthread -lpcap --std=c++11 -Wl,--wrap,socket \
		   -Wl,--wrap,bind \
		   -Wl,--wrap,connect \
		   -Wl,--wrap,accept \
		   -Wl,--wrap,listen \
		   -Wl,--wrap,read \
		   -Wl,--wrap,write \
		   -Wl,--wrap,close \
		   -Wl,--wrap,getaddrinfo \


echo_client:
	$(CC) ../checkpoints/echo_client.c ../checkpoints/unp.c basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

echo_server:
	$(CC) ../checkpoints/echo_server.c ../checkpoints/unp.c basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

perf_client:
	$(CC) ../checkpoints/perf_client.c ../checkpoints/unp.c basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

perf_server:
	$(CC) ../checkpoints/perf_server.c ../checkpoints/unp.c basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

flow_client:
	$(CC) test_flow_control_client.cpp ../checkpoints/unp.c basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

flow_server:
	$(CC) test_flow_control_server.cpp ../checkpoints/unp.c basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

device:
	$(CC) test_device.cpp basic.cpp device.cpp packetio.cpp route.cpp arp.cpp ${LDFLAGS} -o $@

arp:
	$(CC) test_arp.cpp basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

route:
	$(CC) test_route.cpp basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

listen:
	$(CC) listen.cpp basic.cpp device.cpp packetio.cpp route.cpp ip.cpp arp.cpp tcp.cpp ${LDFLAGS} -o $@

prefix:
	$(CC) test_longest_prefix.cpp basic.cpp device.cpp packetio.cpp route.cpp arp.cpp ${LDFLAGS} -o $@

clean:
	rm -rf device arp listen route prefix echo_client echo_server perf_client perf_server flow_client flow_server
 