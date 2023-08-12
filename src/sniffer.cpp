//http://yuba.stanford.edu/~casado/pcap/section1.html
//https://dev.to/fmtweisszwerg/cc-how-to-get-all-interface-addresses-on-the-local-device-3pki
#include <iostream>
#include "sniffer.hpp"
#include <fstream>
#include <sys/socket.h>
#include <sys/types.h>

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
                if (p_ifaddr->ifa_addr != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_addr))->sin_addr, interf.ip_4, INET_ADDRSTRLEN);
                }
                if (p_ifaddr->ifa_netmask != nullptr) {
                    inet_ntop(addr_family,&((struct sockaddr_in*)(p_ifaddr->ifa_netmask))->sin_addr, interf.nmsk_4, INET_ADDRSTRLEN);
                }
            } else if (addr_family == AF_INET6) {

            }

            interfaces.push_back(interf);
        }
    }
}

int writeToFile() {
    
}

int main(int argc, char *argv[]) {
    // Parameter handling
    if (argc != 1) {
        std::cout << "Invalid amount of parameters. \nusage: " << argv[0] << "\n";
        exit(1);
    }

    std::cout << "Searching for interfaces...\n";
    std::vector<interface> availInterfaces;
    availInterfaces = getInterfaces();

    for (int i = 0; i < availInterfaces.size(); ++i) {
        interface interf = availInterfaces[i];
        if (interf.addr_family == AF_INET) { // IPv4 address
            std::cout << "\tInterface \"" << interf.name << "\",\t" << "Ip: " << interf.ip_4 << ",\tNetmask: " >> interf.nmsk_4 << ".\n";
        } else {    // Must be IPv6
            std::cout << "\tInterface \"" << interf.name << "\"," << "Ip: " << interf.ip_4 << "\n";
        }
    }


    // Main file that will be written to
    std::ofstream datafile(argv[1]);
    // Make a backup file in case of data corruption
    std::ofstream backup(argv[1]);

    
    
    exit(0);
}