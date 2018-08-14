#ifndef _IP_MANAGER_H
#define _IP_MANAGER_H
#include <stdint.h>
#include <netinet/in.h>

#define IN
#define OUT

#pragma pack(push, 1)
class IpManager final {
    public: // public static constants
        static const size_t LENGTH = 4;

    private: // private member variable
        uint8_t ipAddress[LENGTH];

    public: // public functions
        // constructors
        IpManager() {}
        IpManager(IN uint8_t *ipAddress);
        IpManager(IN uint32_t ipAddress);
        IpManager(IN char *ipAddressString);
        IpManager(IN struct in_addr laddr);

        // overload operators
        operator uint8_t *() { return ipAddress; } // getter
        void operator =  (IN const uint8_t *ipAddress) { memcpy(this->ipAddress, ipAddress, LENGTH); }
        bool operator == (IN IpManager &ipManager) { return !memcmp(this->ipAddress, ipManager, LENGTH); }
        bool operator == (IN const uint8_t *ipAddress) { return !memcmp(this->ipAddress, ipAddress, LENGTH); }
        bool operator != (IN IpManager &ipManager) { return memcmp(this->ipAddress, ipManager, LENGTH); }
        bool operator != (IN const uint8_t *ipAddress) { return memcmp(this->ipAddress, ipAddress, LENGTH); }

        // functions
        static void printIpAddress(IN const char *prefix, IN uint8_t *ipAddress);
        void printIpAddress(IN const char *prefix);
};
#pragma pack(pop)
#endif
