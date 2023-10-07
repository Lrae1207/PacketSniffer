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
    printClamped("MAC-source", 20 , BLUE);
    printClamped("MAC-destination", 20 , BLUE);
    printClamped("Ethernet Type", 20 , BLUE);
    printClamped("IP-Source", 20, BLUE);
    printClamped("IP-Destination",20, BLUE);
    printClamped("Length",10, BLUE);
    printClamped("TCP-source",20, BLUE);
    printClamped("TCP-destination",20, BLUE);
}


std::string compileString(u_char chr[], size_t n) {
    std::string str = "";
    for (int i = 0; i < n; ++i) {
        str += chr[n];
    }
    return str;
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

            if (addr_family == AF_INET) { // IPv4
                interf.psuedonym = p_ifaddr->ifa_name;
                interf.psuedonym += "_v4";
                if (p_ifaddr->ifa_addr != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_addr))->sin_addr, interf.ip_4, INET_ADDRSTRLEN);
                }
                if (p_ifaddr->ifa_netmask != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_netmask))->sin_addr, interf.nmsk_4, INET_ADDRSTRLEN);
                }
                interfaces.push_back(interf);
            } else if (addr_family == AF_INET6) { // IPv6
                interf.psuedonym = p_ifaddr->ifa_name;
                interf.psuedonym += "_v6";
                if (p_ifaddr->ifa_addr != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in6*)(p_ifaddr->ifa_addr))->sin6_addr, interf.ip_6, INET6_ADDRSTRLEN);
                }
                if (p_ifaddr->ifa_netmask != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in6*)(p_ifaddr->ifa_netmask))->sin6_addr, interf.nmsk_6, INET6_ADDRSTRLEN);
                }
                interfaces.push_back(interf);
            }
        }
    }
    return interfaces;
}

// Unfortunate global variables
pcap_t *h_pcap;
std::vector<packet_data> packetLog = {};

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

void capture_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int pckt_num = 0;

    // Clear screen and re-print headers followed by data in packetLog
    system("clear");
    printHeaders();
    std::cout << "\n";

    for (size_t i = 0; i < packetLog.size(); ++i) {
        packet_data pack = packetLog[i];

        printClamped(std::to_string(pack.index), 10, YELLOW);
        
        std::string etherSrc = etherToStr(pack.eth->src);
        std::string etherDest = etherToStr(pack.eth->dest);
        
        printClamped(etherSrc, 20, GREEN);
        printClamped(etherDest, 20, RED);

        if(pack.eth->type == ETHERTYPE_IP) {
            printClamped("ETH_IP(" + std::to_string(pack.eth->type) + ")", 20, CYAN);
        } else if(pack.eth->type == ETHERTYPE_ARP) {
            printClamped("ETH_ARP(" + std::to_string(pack.eth->type) + ")", 20, CYAN);
        } else if(pack.eth->type == ETHERTYPE_REVARP) {
            printClamped("ETH_REVAR(" + std::to_string(pack.eth->type) + ")", 20, CYAN);
        } else {
            printClamped("UNKNOWN(" + std::to_string(pack.eth->type) + ")", 20, CYAN);
        }

        if (pack.ipErr == "") {
            printClamped(inet_ntoa(pack.ip->ip_src), 20, GREEN);
            printClamped(inet_ntoa(pack.ip->ip_dst), 20, RED);
        } else {
            printClamped(pack.ipErr, 20, GREEN);
            printClamped(pack.ipErr, 20, RED);
        }

        // Seg fault here
        int packLen = pkthdr->len;
        printClamped(std::to_string(packLen), 10, MAGENTA);

        if (pack.tcpErr == "") {
            printClamped(std::to_string(pack.tcp->th_sport), 20, GREEN);
            printClamped(std::to_string(pack.tcp->th_dport), 20, RED);
        } else {
            printClamped(pack.tcpErr, 20, GREEN);
            printClamped(pack.tcpErr, 20, RED);
        }
        std::cout << "\n";
    }

    // Get data for the new packet
    struct packet_data pdata;
    struct ether_data *edata;
    struct ip_data    *ipdata;
    struct tcp_data   *tcpdata;
    u_char              *payload;
    
    // Get Ethernet data
    edata = (struct ether_data *)packet;

    // Get IP data
    ipdata = (struct ip_data*)(packet + ETHER_HEADER_LEN);
    u_int ipLen = IP_HL(ipdata)*4;
    pdata.ipSize = ipLen;
    if (ipLen < 20) {
        pdata.ipErr = "BAD HEADER LENGTH";
        pdata.tcpErr = "UNCALCULATED";
        pdata.eth = edata;
        pdata.ip = ipdata;
        pdata.index = pckt_num;
        packetLog.push_back(pdata);
        if (packetLog.size() > logCap) {
            packetLog.erase(packetLog.begin());
        }
        ++pckt_num;
        return;
    }

    // Get TCP data
    tcpdata = (struct tcp_data*)(packet + ETHER_HEADER_LEN + ipLen);
    u_int tcpLen = TH_OFF(tcpdata)*4;
    pdata.tcpSize = tcpLen;
    if (tcpLen < 20) {
        pdata.tcpErr = "BAD HEADER LENGTH";
        pdata.eth = edata;
        pdata.ip = ipdata;
        pdata.index = pckt_num;
        packetLog.push_back(pdata);
        if (packetLog.size() > logCap) {
            packetLog.erase(packetLog.begin());
        }
        ++pckt_num;
        return;
    }

    // Calculate payload start position
    payload = (u_char *)(packet + ETHER_HEADER_LEN + ipLen + tcpLen);
    pdata.payload = payload;
    pdata.payloadLen = pkthdr->len;
    
    // Fill complete packet structure and add packet to temporary log
    pdata.eth = edata;
    pdata.ip = ipdata;
    pdata.index = pckt_num;
    packetLog.push_back(pdata);
    if (packetLog.size() > logCap) {
        packetLog.erase(packetLog.begin());
    }
    ++pckt_num;
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
        if (interf.sa_family == AF_INET) { /* IPv4 address */
            std::cout << "\tInterface \"" << interf.psuedonym << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmask: " << interf.nmsk_4 << "\n";
        } else if (interf.sa_family == AF_INET6) { /* IPv6 address */
            std::cout << "\tInterface \"" << interf.psuedonym << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmask: " << interf.nmsk_6 << "\n";
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

            // Shadows over other local declaration of availInterfaces
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
