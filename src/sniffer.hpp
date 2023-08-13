#include <pcap.h>
#include <string>
#include <vector>

struct interface {
    sa_family_t sa_family;
    std::string name;

    char ip_4[INET_ADDRSTRLEN];
    char nmsk_4[INET_ADDRSTRLEN];

    char ip_6[INET6_ADDRSTRLEN];
    char nmsk_6[INET6_ADDRSTRLEN];
};

std::vector<interface> getInterfaces();
std::string selectInterface();
void startCapture(interface interf, int maxCaptures);