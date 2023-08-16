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
    printClamped("Ethernet Type", 20 , BLUE);
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

// Unfortunate global variables
pcap_t *h_pcap;
std::vector<packet_data> packetLog = {};

// Packet display settings
int logCap = 10;
int maxCaptures = 100000;

struct ether_data getEtherData(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ether_header *p_eth = (struct ether_header *) packet;
    struct ether_data edata;

    edata.src = ether_ntoa((const struct ether_addr *)&p_eth->ether_shost);
    edata.dest = ether_ntoa((const struct ether_addr *)&p_eth->ether_shost);
    edata.type = p_eth->ether_type;

    return edata;
}
/*
struct ip_data getIPData(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    const struct ip* ip;
    struct ip_data ipdata;

    ipdata.src = "NULL";
    ipdata.dest = "NULL";

    u_int hdrlen,off,version;
    int i;
    int len = ntohs(ip->ip_len);

    u_int length = pkthdr-&len;
    ip = (struct ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    if (length < sizeof(struct ip)) {
        ipdata.src = "BAD LENGTH";
        ipdata.dest = "BAD LENGTH";
        return ipdata;
    }

    hdrlen  = IP_HL(ip);
    version = IP_V(ip);

    ipdata.hdrlen = hdrlen;
    ipdata.version = version;
    ipdata.offset = off;

    if (version != 4)
    {
        ipdata.src = "BAD VERSION";
        ipdata.dest = "BAD VERSION";
        return ipdata;
    }

    if (hdrlen < 5)
    {
        ipdata.src = "BAD HEADER LENGTH";
        ipdata.dest = "BAD HEADER LENGTH";
        return ipdata;
    }

    if (length < len) {
        ipdata.src = "MISSING " + len - length + " BYTES";
        ipdata.dest = "MISSING " + len - length + " BYTES";
        return ipdata;
        //len - length
    }

    off = ntohs(ip->ip_off);
    if ((off &apm; 0x1fff) == 0 ) {
        ipdata.src = inet_ntoa(ip->ip_src);
        ipdata.dest = inet_ntoa(ip->ip_dst);
    }
    return ipdata;
}
*/
u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    int len = = ntohs(ip->ip_len)
    const struct my_ip* ip;
    u_int length = pkthdr-&len;
    u_int hlen,off,version;
    int i;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
      return NULL;
    }

    /* check header length */
    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off &apm; 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout,"IP: ");
        fprintf(stdout,"%s ",
                inet_ntoa(ip->ip_src));
        fprintf(stdout,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),
                hlen,version,len,off);
    }

    return NULL;
}


void capture_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    static int pckt_num = 0;

    // Clear screen and re-print headers followed by data in packetLog
    system("clear");
    printHeaders();
    std::cout << "\n";
    for (int i = 0; i < packetLog.size(); ++i) {
        packet_data pack = packetLog[i];
        printClamped(std::to_string(pack.index), 10, YELLOW);
        printClamped(pack.eth.src, 20, GREEN);
        printClamped(pack.eth.dest, 20, RED);

        if(pack.eth.type == ETHERTYPE_IP) {
            printClamped("ETH_IP(" + std::to_string(pack.eth.type) + ")", 20, CYAN);
        } else if(pack.eth.type == ETHERTYPE_ARP) {
            printClamped("ETH_ARP(" + std::to_string(pack.eth.type) + ")", 20, CYAN);
        } else if(pack.eth.type == ETHERTYPE_REVARP) {
            printClamped("ETH_REVAR(" + std::to_string(pack.eth.type) + ")", 20, CYAN);
        } else {
            printClamped("UNKNOWN(" + std::to_string(pack.eth.type) + ")", 20, CYAN);
        }

        std::cout << "\n";
    }

    struct ether_data edata = getEtherData(args, pkthdr, packet);

    // Fill packet structure and add packet to temporary log
    struct packet_data pdata;
    pdata.eth = edata;
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
            std::string userInput;

            // std::cin >> userInput doesn't account for whitespace.
            // std::getline works better for arguments
            std::getline(std::cin, userInput);
            std::vector<std::string> inputArgs = {};

            // Split input by whitespace
            std::string temp = "";
            for (int i = 0; i < userInput.size(); ++i) {
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
