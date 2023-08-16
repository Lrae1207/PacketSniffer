//\usr\include\x86_64-linux-gnu\bits\socket.h
//\usr\include\linux\if_arp.h
//https://upload.wikimedia.org/wikipedia/commons/3/37/Netfilter-packet-flow.svg
#include "sniffer.hpp"
#include "colors.hpp"
#include <fstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <errno.h>
#include <netpacket/packet.h>
#include <cstring>
#include <pcap/pcap-int.h>
#include <iostream>

// Output handling

// Print n characters of buffer and fill any remaining space with ' 's
void printClamped(std::string buffer, int n, std::string color) {
    std::cout << color;
    for (int i = 0; i < n; ++i) {
        if (i < buffer.size()) {
            std::cout << buffer[i];
        } else {
            std::cout << ' ';
        }
    }
    std::cout << RESET;
}

void printHeaders() {
    printClamped("Index", 10 , BLUE);
    printClamped("MAC-source", 20 , BLUE);
    printClamped("MAC-destination", 20 , BLUE);
}

// Packet capture functionality:

// Put list of interfaces in a vector and return it
std::vector<interface> getInterfaces() {
    std::vector<interface> interfaces;
    struct ifaddrs* p_iffirst;
    
    if (getifaddrs(&p_iffirst) == 0) {
        for (struct ifaddrs* p_ifaddr = p_iffirst; p_ifaddr != nullptr; p_ifaddr = p_ifaddr->ifa_next) {
            interface interf;

            interf.name = p_ifaddr->ifa_name;
            
            sa_family_t addr_family = p_ifaddr->ifa_addr->sa_family;
            interf.sa_family = addr_family;
            // IPv4
            if (addr_family == AF_INET) {
                interf.psuedonym = p_ifaddr->ifa_name;
                interf.psuedonym += "_v4";
                if (p_ifaddr->ifa_addr != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_addr))->sin_addr, interf.ip_4, INET_ADDRSTRLEN);
                }
                if (p_ifaddr->ifa_netmask != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_netmask))->sin_addr, interf.nmsk_4, INET_ADDRSTRLEN);
                }
                interfaces.push_back(interf);
            } else if (addr_family == AF_INET6) {
                interf.psuedonym = p_ifaddr->ifa_name;
                interf.psuedonym += "_v6";
                if (p_ifaddr->ifa_addr != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in6*)(p_ifaddr->ifa_addr))->sin6_addr, interf.ip_6, INET6_ADDRSTRLEN);
                }
                if (p_ifaddr->ifa_netmask != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in6*)(p_ifaddr->ifa_netmask))->sin6_addr, interf.nmsk_6, INET6_ADDRSTRLEN);
                }
                interfaces.push_back(interf);
            } else if (addr_family == AF_PACKET) {
                interf.psuedonym = p_ifaddr->ifa_name;
                interf.psuedonym += "_pk";
                interfaces.push_back(interf);
            }
        }
    }
    return interfaces;
}

pcap_t *h_pcap;

struct ether_data getEtherData(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    struct ether_header *p_eth = (struct ether_header *) packet;
    struct ether_data edata;

    edata.src = ether_ntoa((const struct ether_addr *)&p_eth->ether_shost);
    edata.dest = ether_ntoa((const struct ether_addr *)&p_eth->ether_shost);
    edata.type = p_eth->ether_type;

    return edata;
}
#include<unistd.h> 
void capture_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int pckt_num = 0;
    std::cout << "\r";
    printClamped(std::to_string(pckt_num), 10, YELLOW);
    
    struct ether_data edata = getEtherData(args, pkthdr, packet);

    printClamped(edata.src, 20, GREEN);
    printClamped(edata.dest, 20, RED);


    
    if(edata.type == ETHERTYPE_IP) {
        /* handle IP packet */
    } else if(edata.type == ETHERTYPE_ARP) {
        /* handle arp packet */
    } else if(edata.type == ETHERTYPE_REVARP) {
        /* handle reverse arp packet */
    }

    ++pckt_num;
}

void startCapture(struct interface interf, int maxCaptures) {
    char errbuf[PCAP_ERRBUF_SIZE];
    h_pcap = pcap_open_live(interf.name.c_str(),BUFSIZ,0,-1,errbuf);
    if (h_pcap == NULL) {
        std::cout << "pcap_open_live():" << errbuf;
        exit(1);
    }
    printHeaders();
    std::cout << "\n";
    pcap_loop(h_pcap, maxCaptures, capture_callback, NULL);
    std::cout << "Max captures reached." << "\n";
}

// Input loop helper functions
void exitProgram() {
    std::cout << "Exiting program. Thank you for using it.\n";
    exit(0);
}

// Input loop functions:
std::string selectInterface(struct interface *p_interfaces) {
    std::cout << "Searching for interfaces...\n";
    std::vector<interface> availInterfaces = getInterfaces();
    struct interface selectedInterf;

    for (int i = 0; i < availInterfaces.size(); ++i) {
        struct interface interf = availInterfaces[i];
        if (interf.sa_family == AF_INET) { // IPv4 address
            std::cout << "\tInterface \"" << interf.psuedonym << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmask: " << interf.nmsk_4 << "\n";
        } else if (interf.sa_family == AF_INET6) { // IPv6 address
            std::cout << "\tInterface \"" << interf.psuedonym << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmask: " << interf.nmsk_6 << "\n";
        } else if (interf.sa_family == AF_PACKET) {
            std::cout << "\tInterface \"" << interf.psuedonym << "\":\n";
        }
    }

    std::string user_input;
    bool isSelected = false;
    std::cout << "Enter \"interfaces\" to show interfaces\n";

    while (!isSelected) {
        std::cout << "Please select a valid interface\n>>";
        std::cin >> user_input;
        for (int i = 0; i < availInterfaces.size(); ++i) {
            isSelected = user_input == availInterfaces[i].psuedonym  || isSelected;
            if (availInterfaces[i].psuedonym == user_input) {
                selectedInterf = availInterfaces[i];
            }
        }

        if (user_input == "exit") {
            exitProgram();
        } else if (!isSelected && user_input == "interfaces") {
            std::cout << "Searching for interfaces...\n";
            std::vector<struct interface> availInterfaces;
            availInterfaces = getInterfaces();

            for (int i = 0; i < availInterfaces.size(); ++i) {
                struct interface interf = availInterfaces[i];
                if (interf.sa_family == AF_INET) { // IPv4 address
                    std::cout << "\tInterface \"" << interf.psuedonym << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmask: " << interf.nmsk_4 << "\n";
                } else {    // Must be IPv6
                    std::cout << "\tInterface \"" << interf.psuedonym << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmask: " << interf.nmsk_6 << "\n";
                }
            }
        } else if (!isSelected && user_input != "interfaces") {
            std::cout << "Phrase/name \"" << user_input << "\" not recognized\n";
        }
    }
    std::cout << "Interface: " << user_input << " selected.\n";
    *p_interfaces = selectedInterf;
    return user_input;
}


int main(int argc, char *argv[]) {
    // Parameter handling
    if (argc != 1) {
        std::cout << "Invalid amount of parameters. \nusage: " << argv[0] << "\n";
        exit(1);
    }
    std::cout << "This program was made by github user Lrae1207 @ https://github.com/Lrae1207. I can be contacted via e-mail lraeprogramming@gmail.com. Thank you for using this little project of mine.\n\n";

    struct interface selectedInterf;
    std::string interfaceName = selectInterface(&selectedInterf);

    bool running = true;

    while (running) {
        if (&selectedInterf == nullptr || interfaceName == "") {
            interfaceName = selectInterface(&selectedInterf);
        } else {
            std::cout << interfaceName << ">>";
            std::string user_input;
            std::cin >> user_input;

            // Check user input
            if (user_input == "exit") {
                exitProgram();
            } else if (user_input == "interfaces") {
                std::cout << "Searching for interfaces...\n";
                std::vector<struct interface> availInterfaces;
                availInterfaces = getInterfaces();

                for (int i = 0; i < availInterfaces.size(); ++i) {
                    struct interface interf = availInterfaces[i];
                    if (interf.sa_family == AF_INET) { // IPv4 address
                        std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmask: " << interf.nmsk_4 << "\n";
                    } else {    // Must be IPv6
                        std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmask: " << interf.nmsk_6 << "\n";
                    }
                }
            } else if (user_input == "select") {
                interfaceName = selectInterface(&selectedInterf);
            } else if(user_input == "start_cap") {
                startCapture(selectedInterf, 10000);
            } else if (user_input == "help") {
                std::cout << "help - displays this message\ninterfaces - displays and resets interfaces\nexit - exits program\nselect - select new interface\nstart_cap - begin capturing packets through the selected interface\n";
            } else {    // No valid input detected
                std::cout << "Enter \"help\" for more info\n";
            }
        }
    }

    return 0;
}
