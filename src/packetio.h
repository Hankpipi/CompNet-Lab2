#include "device.h"

int setFrameReceiveCallback(frameReceiveCallback callback);
int myFrameReceivedCallback(const void* buf, int len, int id);
u_char* strToMMacToStrac(const u_char* mac);