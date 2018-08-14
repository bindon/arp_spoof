#ifndef _ARP_H
#define _ARP_H
#include <pcap.h>
#include <main.h>
#include <stdint.h>

// Ethernet Constants
#define ETHERNET_TYPE_ARP 0x0806

// ARP Constants
#define ARP_HARDWARE_TYPE_ETHERNET   0x01
#define ARP_PROTOCOL_TYPE_IP         0x0800
#define ARP_HARDWARE_LENGTH_ETHERNET 0x06
#define ARP_PROTOCOL_LENGTH_IP       0x04
#define ARP_OPERATION_REQUEST        0x01
#define ARP_OPERATION_REPLY          0x02
#define RARP_OPERATION_REQUEST       0x03
#define RARP_OPERATION_REPLY         0x04

// ARP Session Node
typedef struct _ArpSession {
    MacManager senderMacAddress;
    MacManager targetMacAddress;
    IpManager  senderIpAddress;
    IpManager  targetIpAddress;
} ArpSession;

#pragma pack(push, 1)
// Ethernet Header Structure
typedef struct _EthernetStructure {
    MacManager destinationMacAddress;
    MacManager sourceMacAddress;
    uint16_t type;
} EthernetStructure;

// ARP Packet Structure
typedef struct _ArpStructure {
    uint16_t   hardwareType;
    uint16_t   protocolType;
    uint8_t    hardwareLength;
    uint8_t    protocolLength;
    uint16_t   operationCode;
    MacManager senderHardwareAddress;
    IpManager  senderProtocolAddress;
    MacManager targetHardwareAddress;
    IpManager  targetProtocolAddress;
} ArpStructure;

// Ethernet + ARP Packet Structure
typedef struct _MergedStructure {
    EthernetStructure ethernetPacket;
    ArpStructure      arpPacket;
} MergedStructure;
#pragma pack(pop)

int receiveSenderMacAddress(IN pcap_t *handle, IN IpManager senderIpAddress, OUT MacManager &senderMacAddress);
int getSenderMacAddress(IN pcap_t *handle, IN MacManager targetMacAddress, IN IpManager targetIpAddress, IN IpManager senderIpAddress, OUT MacManager &senderMacAddress);
int infectSender(IN pcap_t *handle, IN MacManager localMacAddress, IN ArpSession arpSession);
int infectSender(IN pcap_t *handle, IN MacManager localMacAddress, IN ArpSession arpSession, IN int count);

#endif
