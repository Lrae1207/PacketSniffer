#include <pcap.h>
#include <string>
#include <vector>

#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <netinet/in.h>

struct interface {
	bool useable = false;
    sa_family_t sa_family;
    std::string name;

    char ip_4[INET_ADDRSTRLEN];
    char nmsk_4[INET_ADDRSTRLEN];

    char ip_6[INET6_ADDRSTRLEN];
    char nmsk_6[INET6_ADDRSTRLEN];
};

#define ETHER_HEADER_LEN 14 // bytes
struct ether_data {
    u_char src[ETHER_ADDR_LEN];
    u_char dest[ETHER_ADDR_LEN];
    u_short type;
};

// Taken from https://www.tcpdump.org/pcap.html
// Based on: https://en.wikipedia.org/wiki/Internet_Protocol_version_4#Header
struct ip_data {
	u_char ip_vhl;		/* version 4 | header length 4 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)

// Based on: https://en.wikipedia.org/wiki/IPv6_packet#Fixed_header
struct ip_data_6 {
	u_char ipv6_vtc; /* version 4 | traffic class 4 */
	u_char ipv6_tcfl; /* second part of traffic class 4 | flow label 4 */
	u_short ipv6_fl; /* second part of flow label 16 */
	u_short ipv6_pl; /* payload length 16 */
	u_char ipv6_next; /* next header 8 */
	u_char ipv6_hl; /* hop limit 8*/
	struct in6_addr ipv6_src,ipv6_dst; /* source and destination */
};
#define IPv6_V(ip)	(((ip)->ipv6_vtc & 0xf0) >> 4)

struct ip_container {
	ip_data ip_v4;
	ip_data_6 ip_v6;
};

struct tcp_data {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	u_long th_seq;		/* sequence number */
	u_long th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

struct packet_data {
    int index;
	int length;
    struct ether_data *eth; /* ETHERNET */
    u_int ipSize; 			/* IP */
    struct ip_data *ip;
	std::string ipErr = "";
    u_int tcpSize;			/* TCP */
    struct tcp_data *tcp;
	std::string tcpErr = "";
	u_char *payload;		/* PAYLOAD */
	u_int payloadLen;
};

// Function declarations
void printClamped(std::string buffer, int n, std::string color);
void printHeaders();
std::string compileString(u_char chr[], size_t n);
std::vector<interface> getInterfaces();
std::string etherToStr(u_char addr[ETHER_ADDR_LEN]);
void capture_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void startCapture(struct interface interf);
void exitProgram();
std::string selectInterface(struct interface *p_interfaces);