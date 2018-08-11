#include <util.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

// Get MAC Address using Interface Name
int getLocalMacAddress(IN char *interfaceName, OUT MacManager &macManager) {
    struct ifreq interfaceRequest;
    int ret = EXIT_FAILURE;
    int fileDescriptor;

    if((fileDescriptor = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        fprintf(stderr, "[-] socket error!\n");
        goto end;
    }

    strncpy(interfaceRequest.ifr_name, interfaceName, IFNAMSIZ-1);
    ioctl(fileDescriptor, SIOCGIFHWADDR, &interfaceRequest);
   
    macManager = (uint8_t *)interfaceRequest.ifr_hwaddr.sa_data;
    macManager.printMacAddress("[*] Local MAC Address : ");

    ret = EXIT_SUCCESS;
end:
    if(fileDescriptor) {
        close(fileDescriptor);
    }

    return ret;
}

// Get IP Address using Interface Name
int getLocalIpAddress(IN char *interfaceName, OUT IpManager &ipManager) {
    struct ifreq interfaceRequest;
    int ret = EXIT_FAILURE;
    int fileDescriptor;

    if((fileDescriptor = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
        fprintf(stderr, "[-] socket error!\n");
        goto end;
    }

    strncpy(interfaceRequest.ifr_name, interfaceName, IFNAMSIZ-1);
    ioctl(fileDescriptor, SIOCGIFADDR, &interfaceRequest);

    ipManager = ((struct sockaddr_in *)&interfaceRequest.ifr_addr)->sin_addr;
    ipManager.printIpAddress("[*] Local IP  Address : ");

    ret = EXIT_SUCCESS;
end:
    if(fileDescriptor) {
        close(fileDescriptor);
    }

    return ret;
}

// Print ARP Packet Information
void printArpPacketInfo(IN ArpStructure arpPacket) {
    MacManager::printMacAddress("  - Sender MAC Address : ", (uint8_t *)arpPacket.senderHardwareAddress);
    MacManager::printMacAddress("  - Target MAC Address : ", (uint8_t *)arpPacket.targetHardwareAddress);
    IpManager::printIpAddress  ( "  - Sender IP  Address : ", (uint8_t *)arpPacket.senderProtocolAddress);
    IpManager::printIpAddress  ( "  - Target IP  Address : ", (uint8_t *)arpPacket.targetProtocolAddress);
}
