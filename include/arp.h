#ifndef _ARP_H
#define _ARP_H
#define IN
#define OUT
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
    uint8_t senderMacAddress[ARP_HARDWARE_LENGTH_ETHERNET];
    uint8_t targetMacAddress[ARP_HARDWARE_LENGTH_ETHERNET];
    uint8_t senderIpAddress[ARP_PROTOCOL_LENGTH_IP];
    uint8_t targetIpAddress[ARP_PROTOCOL_LENGTH_IP];
} ArpSession;

#pragma pack(push, 1)
// Ethernet Header Structure
typedef struct _EthernetStructure {
    uint8_t  destinationMacAddress[6];
    uint8_t  sourceMacAddress[6];
    uint16_t type;
} EthernetStructure;

// ARP Packet Structure
typedef struct _ArpStructure {
    uint16_t hardwareType;
    uint16_t protocolType;
    uint8_t  hardwareLength;
    uint8_t  protocolLength;
    uint16_t operationCode;
    uint8_t  senderHardwareAddress[ARP_HARDWARE_LENGTH_ETHERNET];
    uint8_t  senderProtocolAddress[ARP_PROTOCOL_LENGTH_IP];
    uint8_t  targetHardwareAddress[ARP_HARDWARE_LENGTH_ETHERNET];
    uint8_t  targetProtocolAddress[ARP_PROTOCOL_LENGTH_IP];
} ArpStructure;

// Ethernet + ARP Packet Structure
typedef struct _MergedStructure {
    EthernetStructure ethernetPacket;
    ArpStructure      arpPacket;
} MergedStructure;
#pragma pack(pop)

int receiveSenderMacAddress(IN pcap_t *handle, IN uint8_t *senderIpAddress, OUT uint8_t *senderMacAddress);
int getSenderMacAddress(IN pcap_t *handle, IN uint8_t *targetMacAddress, IN uint8_t *targetIpAddress, IN uint8_t *senderIpAddress, OUT uint8_t *senderMacAddress);
int infectSender(IN pcap_t *handle, IN uint8_t *localMacAddress, IN ArpSession arpSession);
int infectSender(IN pcap_t *handle, IN uint8_t *localMacAddress, IN ArpSession arpSession, IN int count);

#endif
