#include <pcap.h>
#include <string>
#include <vector>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

struct interface {
    sa_family_t sa_family;
    std::string name;
    std::string psuedonym;

    char ip_4[INET_ADDRSTRLEN];
    char nmsk_4[INET_ADDRSTRLEN];

    char ip_6[INET6_ADDRSTRLEN];
    char nmsk_6[INET6_ADDRSTRLEN];
};

struct ether_data {
    char *src;
    char *dest;
    u_int16_t type;
};