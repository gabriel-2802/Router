#ifndef ROUTER_LIB_H
#define ROUTER_LIB_H


#include <unistd.h>
#include <array>
#include <cstring> 
using namespace std;

enum icmp_types {
	ECHO_REPLY = 0,
	DEST_UNREACH = 3,
	TTL_EXCEEDED = 11,
};

typedef array<uint8_t, 6> mac_addr_t;
typedef uint32_t ip_addr_t;

#define MAX_RTABLE_SIZE 200'000'000
#define TTL 64

// used for ether type
#define ETH_IPV4 0x0800
#define ETH_ARP 0x0806

#define IP_ICMP 1
#define MAC_BROADCAST 0xFF

class Packet{
	public:
		size_t len;
		char buff[MAX_PACKET_LEN];
		int interface;
		ip_addr_t dest_ip;


        Packet() {
            len = 0;
            interface = -1;
            memset(buff, 0, MAX_PACKET_LEN);
            dest_ip = 0;
        }

        Packet(char *buff, int len, int interface) {
            this->len = len;
            this->interface = interface;
            memset(this->buff, 0, MAX_PACKET_LEN);
            memcpy(this->buff, buff, len);
        }

		Packet(char *buff, int len, int interface, ip_addr_t dest_ip) {
			this->len = len;
			this->interface = interface;
			memset(this->buff, 0, MAX_PACKET_LEN);
			memcpy(this->buff, buff, len);
			this->dest_ip = dest_ip;
		}


		void add_dest_mac(mac_addr_t mac) {
			ether_header *eth_hdr = (ether_header *) buff;
			memcpy(eth_hdr->ether_dhost, mac.begin(), 6);
		}
};

#endif // ROUTER_LIB_H
