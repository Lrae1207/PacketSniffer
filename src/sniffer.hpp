#include <pcap.h>
#include <string>
#include <vector>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

// stolen from pcap site
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

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
    std::string src;
    std::string dest;
    u_int16_t type;
};

struct ip_data {
    int hdrlen;
    std::string src;
    std::string dest;
    int version;
    int len;
    int offset;
};

struct packet_data {
    int index;
    ether_data eth;
};
void printClamped(std::string buffer, int n, std::string color);
