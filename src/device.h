/**
* @file device .h
* @brief Library supporting network device management .
*/
#ifndef DEVICE_H_
#define DEVICE_H_
#include "basic.h"

struct Device {
    int id;
    const char* name;
    const u_char* mac;
    in_addr dev_ip;
    in_addr subnetMask;
    in_addr ip;
    pcap_t* pcap;
    std::thread t;
    std::thread broadcastRouteTable;
    frameReceiveCallback frameCallback;

    Device();
    Device(int _id, const char* _name);
    ~Device();
    /*
   * @send a frame to destmac
   * @param buf buffer of payload
   * @param len length of payload
   * @param ethtype type of eth, don't forget the byte order
   * @param destmac destination
   */
    int sendFrame(const void* buf, int len, int ethtype, const void* destmac) const;
    void printDeviceInfo();
};
struct callback_args {
    int id;
    Device* dev;
    callback_args(int _id, Device* _dev): id(_id), dev(_dev){};
};

struct DevicePool {
    std::vector<Device*> device_list;
    frameReceiveCallback frameCallback;
    /**
    * Add a device to the library for sending / receiving packets .
    *
    * @param device Name of network device to send / receive packet on.
    * @return A non - negative _device - ID_ on success , -1 on error .
    */
    int addDevice(const char* dev_name);
    /**
    * Find a device added by ‘addDevice ‘.
    *
    * @param device Name of the network device .
    * @return A non - negative _device - ID_ on success , -1 if no such device
    * was found .
    */
    int findDevice(const char* dev_name);
    Device* findDevice(in_addr src, in_addr dst);
    int setFrameReceiveCallback(frameReceiveCallback callback);
    void StartListening();
};
extern DevicePool pool;

void pcap_callback(u_char* args, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
void device_loop(Device* dev);
#endif