//http://yuba.stanford.edu/~casado/pcap/section1.html
//https://dev.to/fmtweisszwerg/cc-how-to-get-all-interface-addresses-on-the-local-device-3pki
#include <iostream>
#include "sniffer.hpp"
#include <fstream>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <errno.h>


// Functionality:
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
                interf.name += "_v4";
                if (p_ifaddr->ifa_addr != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_addr))->sin_addr, interf.ip_4, INET_ADDRSTRLEN);
                }
                if (p_ifaddr->ifa_netmask != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_netmask))->sin_addr, interf.nmsk_4, INET_ADDRSTRLEN);
                }
                interfaces.push_back(interf);
            } else if (addr_family == AF_INET6) {
                interf.name += "_v6";
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
/*
struct pcap {
    int fd;
    int snapshot;
    int linktype;
    int tzoff;
    int offset;

    struct pcap_sf sf;
    struct pcap_md md;
    
    int bufsize;
    u_char *buffer;
    u_char *bp;
    int cc;
     
    u_char *pkt;

    struct bpf_program fcode;

    char errbuf[PCAP_ERRBUF_SIZE];
};
*/
void startCapture(interface interf, int maxCaptures) {
    char errbuf[PCAP_ERRBUF_SIZE];
    u_char *packet;
    pcap_t *desc = pcap_open_live(&interf.name,BUFSIZ,0,-1,errbuf);
    if (desc == NULL) {
        perror("pcap_open_live()");
        exit(1);
    }
    for (int i = 0; i < maxCaptures; ++i) {

    }
}

// Input loop helper functions
void exitProgram() {
    std::cout << "Exiting program. Thank you for using it.\n";
    exit(0);
}

// Input loop functions:
std::string selectInterface(std::vector<interface> *p_interfaces) {
    std::cout << "Searching for interfaces...\n";
    std::vector<interface> availInterfaces;
    availInterfaces = getInterfaces();

    for (int i = 0; i < availInterfaces.size(); ++i) {
        interface interf = availInterfaces[i];
        if (interf.sa_family == AF_INET) { // IPv4 address
            std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmask: " << interf.nmsk_4 << "\n";
        } else {    // Must be IPv6
            std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmask: " << interf.nmsk_6 << "\n";
        }
    }

    std::string user_input;
    bool isSelected = false;
    std::cout << "Enter \"interfaces\" to show interfaces\n";

    while (!isSelected) {
        std::cout << "Please select a valid interface\n>>";
        std::cin >> user_input;
        for (int i = 0; i < availInterfaces.size(); ++i) {
            isSelected = user_input == availInterfaces[i].name  || isSelected;
        }

        if (user_input == "exit") {
            exitProgram();
        } else if (!isSelected && user_input == "interfaces") {
            std::cout << "Searching for interfaces...\n";
            std::vector<interface> availInterfaces;
            availInterfaces = getInterfaces();

            for (int i = 0; i < availInterfaces.size(); ++i) {
                interface interf = availInterfaces[i];
                if (interf.sa_family == AF_INET) { // IPv4 address
                    std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmask: " << interf.nmsk_4 << "\n";
                } else {    // Must be IPv6
                    std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmask: " << interf.nmsk_6 << "\n";
                }
            }
        } else if (!isSelected && user_input != "interfaces") {
            std::cout << "Phrase/name \"" << user_input << "\" not recognized\n";
        }
    }
    std::cout << "Interface: " << user_input << " selected.\n";
    *p_interfaces = availInterfaces;
    return user_input;
}


int main(int argc, char *argv[]) {
    // Parameter handling
    if (argc != 1) {
        std::cout << "Invalid amount of parameters. \nusage: " << argv[0] << "\n";
        exit(1);
    }
    std::cout << "This program was made by github user Lrae1207 @ https://github.com/Lrae1207. I can be contacted via e-mail lraeprogramming@gmail.com. Thank you for using this little project of mine.\n\n";

    std::vector<interface> interfaces;

    std::string interfaceName = selectInterface(&interfaces);
    interface selectedInterf;

    for (int i = 0; i < interfaces.size(); ++i) {
        if (interfaces[i].name == interfaceName) {
            selectedInterf = interfaces[i];
        }
    }

    bool running = true;

    while (running) {
        if (interfaces.size() == 0 || &selectedInterf == nullptr || interfaceName == "") {
            interfaceName = selectInterface(&interfaces);
        } else {
            std::cout << interfaceName << ">>";
            std::string user_input;
            std::cin >> user_input;

            // Check user input
            if (user_input == "exit") {
                exitProgram();
            } else if (user_input == "interfaces") {
                std::cout << "Searching for interfaces...\n";
                std::vector<interface> availInterfaces;
                availInterfaces = getInterfaces();

                for (int i = 0; i < availInterfaces.size(); ++i) {
                    interface interf = availInterfaces[i];
                    if (interf.sa_family == AF_INET) { // IPv4 address
                        std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv4: " << interf.ip_4 << ",\n\t\tNetmask: " << interf.nmsk_4 << "\n";
                    } else {    // Must be IPv6
                        std::cout << "\tInterface \"" << interf.name << "\":\n\t\t" << "Ipv6: " << interf.ip_6 << ",\n\t\tNetmask: " << interf.nmsk_6 << "\n";
                    }
                }
            } else if (user_input == "select") {
                interfaceName = selectInterface(&interfaces);
                for (int i = 0; i < interfaces.size(); ++i) {
                    if (interfaces[i].name == interfaceName) {
                        selectedInterf = interfaces[i];
                    }
                }
            } else if (user_input == "help") {
                std::cout << "help - displays this message\ninterfaces - displays and resets interfaces\nexit - exits program\nselect - select new interface\n";
            } else {    // No valid input detected
                std::cout << "Enter \"help\" for more info\n";
            }
        }
    }

    exit(0);
}