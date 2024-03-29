//-pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused
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
    for (size_t i = 0; i < n; ++i) {
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
    printClamped("Ethernet Type", 20 , BLUE);
    printClamped("IP-Source", IPV6MAXSTRINGLENGTH+1, BLUE);
    printClamped("IP-Destination",IPV6MAXSTRINGLENGTH+1, BLUE);
    printClamped("Length",10, BLUE);
}

// Packet capture functionality:

int getIndexByName(std::string name, std::vector<interface> interfaces) {
    for (int i = 0; i < interfaces.size(); ++i) {
        if (interfaces[i].name == name) {
            return i;
        }
    }
    return -1;
}

// Put list of interfaces in a vector and return it
std::vector<interface> getInterfaces() {
    std::vector<interface> interfaces;
    struct ifaddrs* p_iffirst;

    if (getifaddrs(&p_iffirst) == 0) {
        for (struct ifaddrs* p_ifaddr = p_iffirst; p_ifaddr != nullptr; p_ifaddr = p_ifaddr->ifa_next) { // Loop through linked list
            interface interf;

            interf.name = p_ifaddr->ifa_name;
            
            sa_family_t addr_family = p_ifaddr->ifa_addr->sa_family;
            interf.sa_family = addr_family;

            int interfaceIndex;

            if ((interfaceIndex = getIndexByName(interf.name,interfaces)) == -1) { // If the list of interfaces does not already contain an instance of the interface
                if (addr_family == AF_INET) { // IPv4
                    if (p_ifaddr->ifa_addr != nullptr) {
                        inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_addr))->sin_addr, interf.ip_4, INET_ADDRSTRLEN);
                    }
                    if (p_ifaddr->ifa_netmask != nullptr) {
                        inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_netmask))->sin_addr, interf.nmsk_4, INET_ADDRSTRLEN);
                    }
                    interf.useable = true;
                } else if (addr_family == AF_INET6) { // IPv6
                    if (p_ifaddr->ifa_addr != nullptr) {
                        inet_ntop(addr_family,&((struct sockaddr_in6*)(p_ifaddr->ifa_addr))->sin6_addr, interf.ip_6, INET6_ADDRSTRLEN);
                    }
                    if (p_ifaddr->ifa_netmask != nullptr) {
                        inet_ntop(addr_family,&((struct sockaddr_in6*)(p_ifaddr->ifa_netmask))->sin6_addr, interf.nmsk_6, INET6_ADDRSTRLEN);
                    }
                    interf.useable = true;
                }

                interfaces.push_back(interf); // Add it
            } else {
                if (addr_family == AF_INET) { // IPv4
                    if (p_ifaddr->ifa_addr != nullptr) {
                        inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_addr))->sin_addr, interfaces[interfaceIndex].ip_4, INET_ADDRSTRLEN);
                    }
                    if (p_ifaddr->ifa_netmask != nullptr) {
                        inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_netmask))->sin_addr, interfaces[interfaceIndex].nmsk_4, INET_ADDRSTRLEN);
                    }
                    interfaces[interfaceIndex].useable = true;
                } else if (addr_family == AF_INET6) { // IPv6
                    if (p_ifaddr->ifa_addr != nullptr) {
                        inet_ntop(addr_family,&((struct sockaddr_in6*)(p_ifaddr->ifa_addr))->sin6_addr, interfaces[interfaceIndex].ip_6, INET6_ADDRSTRLEN);
                    }
                    if (p_ifaddr->ifa_netmask != nullptr) {
                        inet_ntop(addr_family,&((struct sockaddr_in6*)(p_ifaddr->ifa_netmask))->sin6_addr, interfaces[interfaceIndex].nmsk_6, INET6_ADDRSTRLEN);
                    }
                    interfaces[interfaceIndex].useable = true;
                }
            }


        }
    }
    return interfaces;
}

// Unfortunate global variables
pcap_t *h_pcap;
std::vector<packet_data*> packetLog = {};

// Packet display settings
size_t logCap = 30;
int maxCaptures = 100000;

std::string etherToStr(u_char addr[ETHER_ADDR_LEN]) {
    std::string res;
    char temp[ETHER_ADDR_LEN];
    for (int i = 0; i < 4; ++i) {
        sprintf(temp, "%X", (unsigned)addr[i]);
        res += (std::string)(temp);
        res += ":";
    }
    sprintf(temp, "%X", (unsigned)addr[5]);
    res += (std::string)(temp);
    return res;
}

packet_data *getPacketData(const struct pcap_pkthdr* pkthdr, const u_char* packet, int pckt_num) {
    // Get data for the new packet
    struct packet_data p;
    struct packet_data *pdata = &p;
    struct ether_data *edata;
    struct ip_data    *ipdata;
    struct ip_container *ipcontainer;
    struct trans_protocol *tpdata;
    u_char            *payload;

    size_t ipSize;
    size_t tpSize;
    u_int ipVersion;

    
    //defaults
    pdata->index = pckt_num;

    pdata->length = pkthdr->len;

    // Get Ethernet data
    edata = (struct ether_data *)packet;
    pdata->eth = edata;

    // Get IP data
    ipdata = (struct ip_data*)(packet + ETHER_HEADER_LEN);
    ipVersion = IP_V(ipdata);
    ipSize = IP_HL(ipdata)*4; // must be at least 20

    if (ipVersion == 4) { // If the version is 4 keep everything the same
        tpdata->protocol_num = ipdata->ip_p;
        tpdata->protocol_data = (void *)(packet + ETHER_HEADER_LEN + ipSize);
        if (ipSize < 20) {
            pdata->err = "IP HEADER MALFORMED";
        } else {
            ipcontainer->ip_v4 = ipdata;
        }
    } else { // Otherwise its 6; convert to v6 header
        struct ip_data_6 *ipdata6 = (struct ip_data_6*)(ipdata);
        ipSize = IPV6_HEADER_SIZE;
        tpdata->protocol_num = ipdata6->ipv6_next;
        tpdata->protocol_data = (void *)(packet + ETHER_HEADER_LEN + ipSize);
        ipcontainer->ip_v6 = ipdata6;
    }

    // Payload position
    payload = (u_char *)(packet + ETHER_HEADER_LEN + ipSize + tpSize);
    pdata->payloadLen = pdata->length - (ETHER_HEADER_LEN + ipSize + tpSize);

    pdata->eth = edata;
    pdata->ip = ipcontainer;
    pdata->tp = tpdata;
    pdata->payload = payload;
    
    return pdata;
}

// Actually capture packets
void capture_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int pckt_num = 0;

    // Clear screen and re-print headers followed by data in packetLog
    //system("clear");
    printHeaders();
    std::cout << "\n";

    for (size_t i = 0; i < packetLog.size(); ++i) {
        if (packetLog[i] == nullptr) {
            continue;
        }
        packet_data pack = *packetLog[i];

        if (pack.err == "") {
            printClamped(pack.err, 100, RED);
            continue;
        }

        printClamped(std::to_string(pack.index), 10, YELLOW);
        
        std::string etherSrc = etherToStr(pack.eth->src);
        std::string etherDest = etherToStr(pack.eth->dest);
        
        //printClamped(etherSrc, 20, GREEN);
        //printClamped(etherDest, 20, RED);

        if (pack.eth != nullptr) {
            if(ntohs(pack.eth->type) == ETHERTYPE_IP) {
                printClamped("ETH_IPV4(" + std::to_string(ntohs(pack.eth->type)) + ")", 20, YELLOW);
            } else if(ntohs(pack.eth->type) == ETHERTYPE_ARP) {
                printClamped("ETH_ARP(" + std::to_string(ntohs(pack.eth->type)) + ")", 20, YELLOW);
            } else if(ntohs(pack.eth->type) == ETHERTYPE_REVARP) {
                printClamped("ETH_REVAR(" + std::to_string(ntohs(pack.eth->type)) + ")", 20, YELLOW);
            } else if(ntohs(pack.eth->type) == ETHERTYPE_IPV6) {
                printClamped("ETH_IPV6(" + std::to_string(ntohs(pack.eth->type)) + ")", 20, YELLOW);
            } else {
                printClamped("UNKNOWN(" + std::to_string(ntohs(pack.eth->type)) + ")", 20, YELLOW);
            }
        } else {
            printClamped("nullptr",20,YELLOW);
        }

        if (pack.ip->ip_v4 != nullptr) {
            printClamped(inet_ntoa(pack.ip->ip_v4->ip_src), IPV6MAXSTRINGLENGTH, GREEN);
            printClamped(inet_ntoa(pack.ip->ip_v4->ip_dst), IPV6MAXSTRINGLENGTH, RED);
        } else if (pack.ip->ip_v6 != nullptr) {
            char src[INET6_ADDRSTRLEN];
            char dest[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6,&pack.ip->ip_v6->ipv6_src, src, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6,&pack.ip->ip_v6->ipv6_dst, dest, INET6_ADDRSTRLEN);
            printClamped(src, IPV6MAXSTRINGLENGTH, GREEN);
            printClamped(dest, IPV6MAXSTRINGLENGTH, RED);
        } else {
            printClamped("nullptr",IPV6MAXSTRINGLENGTH,GREEN);
            printClamped("nullptr",IPV6MAXSTRINGLENGTH,RED);
        }

        int packLen = pack.length;
        printClamped(std::to_string(packLen), 10, MAGENTA);

        size_t previewSize = 20;
        std::string payloadPreview;
        size_t payloadIndex = 0;
        while (payloadIndex < previewSize && payloadIndex < pack.payloadLen) {
            payloadPreview += pack.payload[payloadIndex++];
        }
        printClamped(payloadPreview, previewSize, RESET);

        std::cout << "\n";
    }

    packet_data *pdata = getPacketData(pkthdr, packet, ++pckt_num);
    
    // Fill complete packet structure and add packet to temporary log
    if (pdata != nullptr) {
        packetLog.push_back(pdata);
    }
    if (packetLog.size() > logCap) {
        packetLog.erase(packetLog.begin());
    }
}

void startCapture(struct interface interf) {
    system("clear");
    char errbuf[PCAP_ERRBUF_SIZE];
    char *ebuf = &errbuf[0];
    // read timeout section https://www.tcpdump.org/manpages/pcap.3pcap.html
    h_pcap = pcap_open_live(interf.name.c_str(),BUFSIZ,1,1000,ebuf);
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

// I can probably replace this
inline void exitProgram() {
    std::cout << "Exiting program. Thank you for using it.\n";
    exit(0);
}

// Input loop functions:
std::string selectInterface(struct interface *p_interfaces) {
    std::cout << "Searching for interfaces...\n";
    std::vector<interface> availInterfaces = getInterfaces();
    struct interface selectedInterf;

    for (size_t i = 0; i < availInterfaces.size(); ++i) {
        struct interface interf = availInterfaces[i];
        if (!interf.useable) { continue; }
        std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmaskv4: " << interf.nmsk_4 << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmaskv6: " << interf.nmsk_6 << "\n";
    }

    std::string user_input;
    bool isSelected = false;
    std::cout << "Enter \"interfaces\" to show interfaces\n";

    while (!isSelected) {
        std::cout << "Please select a valid interface\n>>";
        std::cin >> user_input;
        for (int i = 0; i < availInterfaces.size(); ++i) {
            isSelected = user_input == availInterfaces[i].name  || isSelected;
            if (availInterfaces[i].name == user_input) {
                selectedInterf = availInterfaces[i];
            }
        }

        if (user_input == "exit") {
            exitProgram();
        } else if (!isSelected && user_input == "interfaces") {
            std::cout << "Searching for interfaces...\n";

            // Shadows over other local declaration of availInterfaces
            std::vector<struct interface> availInterfaces;
            availInterfaces = getInterfaces();

            for (int i = 0; i < availInterfaces.size(); ++i) {
                struct interface interf = availInterfaces[i];
                if (!interf.useable) { continue; }
                std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmaskv4: " << interf.nmsk_4 << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmaskv6: " << interf.nmsk_6 << "\n";
            }
        } else if (!isSelected && user_input != "interfaces") {
            std::cout << "Phrase/name \"" << user_input << "\" not recognized\n";
        }
    }
    //std::cout << "Interface: " << user_input << " selected.\n";
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
        // First condition may be unnecessary
        if (&selectedInterf == nullptr || interfaceName == "") {
            interfaceName = selectInterface(&selectedInterf);
        } else {
            std::cout << interfaceName << ">>";
            std::string userInput;

            // std::cin >> userInput doesn't account for whitespace.
            // std::getline works better for arguments
            std::getline(std::cin, userInput);
            std::vector<std::string> inputArgs = {};

            // Split input by whitespace
            std::string temp = "";
            for (size_t i = 0; i < userInput.size(); ++i) {
                if (userInput[i] == ' ' || userInput[i] == '\t') {
                    inputArgs.push_back(temp);
                    temp = "";
                } else {
                    temp += userInput[i];
                }
            }
            inputArgs.push_back(temp);

            // Check user input(I know it looks disgusting)
            if (inputArgs.size() == 1) {
                if (inputArgs[0] == "exit") {
                    exitProgram();
                } else if (inputArgs[0] == "interfaces") {
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
                } else if (inputArgs[0] == "select") {
                        interfaceName = selectInterface(&selectedInterf);
                } else if (inputArgs[0] == "start_cap") {
                    startCapture(selectedInterf);
                } else if (inputArgs[0] == "show_opt") {
                    std::cout << "Options:\n\tlog_cap: " << logCap << " - Maximum amount of packets to show information for\n\tmax_caps: " << maxCaptures << " - Maximum amount of captures before the programs stops the capture loop." << "\n";
                } else if (inputArgs[0] == "help") {
                    std::cout << "help - displays this message\ninterfaces - displays and resets interfaces\nexit - exits program\nselect - select new interface\nstart_cap - begin capturing packets through the selected interface\nset_opt <option> <value> - set an option to a given value\nshow_opt - show current options\n";
                } else if (inputArgs[0] != "") {    // No valid input detected
                    std::cout << "Input not recognized as a command. Make sure you didn't forget any arguments. Enter \"help\" for more info\n";
                }
            } else if (inputArgs.size() == 3) {
                if (inputArgs[0] == "set_opt" && inputArgs[1] == "log_cap") {
                    try {
                        int temp = std::stoi(inputArgs[2]);
                        if (temp < 0) {
                            throw 1;
                        }
                        logCap = temp;
                        std::cout << GREEN << "log_cap set to: " << BLUE << logCap << RESET << "\n";
                    } catch (...) {
                        std::cout << RED << "Invalid argument in <value> field\n" << RESET;
                    }
                } else if (inputArgs[0] == "set_opt" && inputArgs[1] == "max_caps") {
                    try {
                        int temp = std::stoi(inputArgs[2]);
                        if (temp < 0) {
                            throw 1;
                        }
                        maxCaptures = temp;
                        std::cout << GREEN << "max_caps set to: " << BLUE << logCap << RESET << "\n";
                    } catch (...) {
                        std::cout << RED << "Invalid argument in <value> field\n" << RESET;
                    }
                }
            }
        }
    }

    return 0;
}
