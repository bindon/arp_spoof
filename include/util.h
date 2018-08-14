#ifndef _UTIL_H
#define _UTIL_H
#include <arp.h>
#include <main.h>
#include <stdint.h>

int getLocalMacAddress(IN char *interfaceName, OUT MacManager &macAddress);
int getLocalIpAddress(IN char *interfaceName, OUT IpManager &ipAddress);
void printArpPacketInfo(IN ArpStructure arpPacket);
#endif
