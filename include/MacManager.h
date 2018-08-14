#ifndef _MAC_MANAGER_H
#define _MAC_MANAGER_H
#include <stdint.h>
#include <string.h>

#define IN
#define OUT

#pragma pack(push, 1)
class MacManager final {
    public: // public static constants
        static const size_t LENGTH = 6;
        
    private: // private member variable
        uint8_t macAddress[LENGTH];

    public:
        // constructors
        MacManager() {}
        MacManager(IN uint8_t *macAddress);

        // overload operators
        operator uint8_t *() { return macAddress; };
        void operator =  (IN const uint8_t *macAddress) { memcpy(this->macAddress, macAddress, LENGTH); }
        bool operator == (IN MacManager &macManager) { return !memcmp(this->macAddress, macManager, LENGTH); }
        bool operator == (IN const uint8_t *macAddress) { return !memcmp(this->macAddress, macAddress, LENGTH); }
        bool operator != (IN MacManager &macManager) { return memcmp(this->macAddress, macManager, LENGTH); }
        bool operator != (IN const uint8_t *macAddress) { return memcmp(this->macAddress, macAddress, LENGTH); }

        // functions
        static void printMacAddress(IN const char *prefix, IN uint8_t *macAddress);
        void printMacAddress(IN const char *macAddress);
        void setBroadcast();
        bool isBroadcast();
};
#pragma pack(pop)
#endif
