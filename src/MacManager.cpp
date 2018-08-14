#include <stdio.h>
#include <MacManager.h>

MacManager::MacManager(IN uint8_t *macAddress) {
    memcpy(this->macAddress, macAddress, LENGTH);
}

void MacManager::printMacAddress(IN const char *prefix, IN uint8_t *macAddress) {
    printf("%s[%02x:%02x:%02x:%02x:%02x:%02x]\n", prefix,
    macAddress[0], macAddress[1], macAddress[2],
    macAddress[3], macAddress[4], macAddress[5]);
}

void MacManager::printMacAddress(IN const char *prefix) {
    printf("%s[%02x:%02x:%02x:%02x:%02x:%02x]\n", prefix,
    macAddress[0], macAddress[1], macAddress[2],
    macAddress[3], macAddress[4], macAddress[5]);
}

void MacManager::setBroadcast() {
    memset(this->macAddress, 0xFF, LENGTH);
}

bool MacManager::isBroadcast() {
    return ((unsigned int)*macAddress) == 0xFFFFFFFF && ((unsigned short)*(macAddress+sizeof(unsigned int))) == 0xFFFF;
}
