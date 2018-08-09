#ifndef _UTIL_H
#define _UTIL_H
#define IN
#define OUT
#include <stdint.h>
#include <arp.h>

// --------------- debug -------------

// --------------- debug -------------

void printMacAddress(IN const char *prefix, IN uint8_t *macAddress);
void printIpAddress(IN const char *prefix, IN uint8_t *ipAddress);
int getLocalMacAddress(IN char *interfaceName, OUT uint8_t *macAddress);
int getLocalIpAddress(IN char *interfaceName, OUT uint8_t *ipAddress);
void printArpPacketInfo(IN ArpStructure arpPacket);
#endif
