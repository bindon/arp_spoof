#ifndef _MAC_MANAGER_H
#define _MAC_MANAGER_H
#include <stdint.h>
#include <string.h>

#define IN
#define OUT

#pragma pack(push, 1)
class MacManager {
    public: // public static constants
        static const size_t LENGTH = 6;
        
    private: // private member variable
        uint8_t macAddress[LENGTH];

    private: // private functions
        void init(IN int character);

    public:
        // constructors
        MacManager();
        MacManager(IN uint8_t *macAddress);

        // overload operators
        operator uint8_t *() { return macAddress; };
        void operator =  (IN const uint8_t *macAddress);
        bool operator == (IN MacManager &macManager);
        bool operator == (IN const uint8_t *macAddress);
        bool operator != (IN MacManager &macManager);
        bool operator != (IN const uint8_t *macAddress);

        // functions
        static void printMacAddress(IN const char *prefix, IN uint8_t *macAddress);
        void printMacAddress(IN const char *macAddress);
        void setBroadcast();
        bool isBroadcast();
};
#pragma pack(pop)
#endif
