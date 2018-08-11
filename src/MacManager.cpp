#include <stdio.h>
#include <MacManager.h>

void MacManager::init(IN int character) {
    memset(macAddress, character, LENGTH);
}

MacManager::MacManager() {
    init(0x00);
}

MacManager::MacManager(IN uint8_t *macAddress) {
    memcpy(this->macAddress, macAddress, LENGTH);
}

void MacManager::operator = (IN const uint8_t *macAddress) {
    memcpy(this->macAddress, macAddress, LENGTH);
}

bool MacManager::operator == (IN MacManager &macManager) {
    return !memcmp(this->macAddress, macManager, LENGTH);
}

bool MacManager::operator == (IN const uint8_t *macAddress) {
    return !memcmp(this->macAddress, macAddress, LENGTH);
}

bool MacManager::operator != (IN MacManager &macManager) {
    return memcmp(this->macAddress, macManager, LENGTH);
}

bool MacManager::operator != (IN const uint8_t *macAddress) {
    return memcmp(this->macAddress, macAddress, LENGTH);
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
    init(0xFF);
}

bool MacManager::isBroadcast() {
    bool isBroadcast = true;
    for(int idx=0; idx<LENGTH; idx++) {
        if(macAddress[idx] != 0xFF) {
           isBroadcast = false;
           break; 
        }
    }
    return isBroadcast;
}
