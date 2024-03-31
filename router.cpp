
#include "include/lib.h"
#include "include/protocols.h"
#include "BinaryTrie.h"
#include "Node.h"
#include "router_lib.h"


#include <iostream>
#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include <optional>
#include <unordered_map>
#include <cstring>	
#include <algorithm>
#include <array>
#include <list>

using namespace std;

#define DEFAULT_TTL 64
#define ICMP_PACKET_SIZE 64
#define ICMP_PAYLOAD_SIZE 8

#define ARP_REQUEST 1
#define ARP_REPLY 2


class Router {
	private:
		BinaryTrie *routing_table;
		unordered_map<ip_addr_t, mac_addr_t> arp_cache;
		list<Packet> waiting_packets;


	public:
		Router(char *file_name) {
			routing_table = new BinaryTrie();
			build_routes(file_name);

			// static mac table
			arp_table_entry *arp_table = new arp_table_entry[6];
			parse_arp_table("arp_table.txt", arp_table);

			for (int i = 0; i < 6; ++i) {
				arp_table_entry *entry = arp_table + i;
				uint8_t *mac = new uint8_t[6];

				mac_addr_t mac_addr;
				copy(entry->mac, entry->mac + 6, mac_addr.begin());

				arp_cache[entry->ip] = mac_addr;
			}
		}

	private:
	 	void build_routes(char *file_name) {
			routing_table = new BinaryTrie();
			route_table_entry *entries = new route_table_entry[MAX_RTABLE_SIZE];
			int len = read_rtable(file_name, entries);

			int valid = 0;
			for (int i = 0; i < len; ++i) {
				route_table_entry *entry = entries + i;
				if ((entry->prefix & entry->mask )== entry->prefix) {
					routing_table->insert(*entry);
				}
			}
		}

		optional<route_table_entry> next_hop(ip_addr_t ip) {
			return routing_table->longest_prefix_match(ip);

		}

		bool crc(iphdr *ip_hdr) {
			uint16_t original_sum = ntohs(ip_hdr->check);
			ip_hdr->check = 0;

			uint16_t *data = (uint16_t *) ip_hdr;
			
			return checksum(data, sizeof(iphdr)) == original_sum;
		}

		bool crc(icmphdr *icmp_hdr) {
			uint16_t original_sum = ntohs(icmp_hdr->checksum);
			icmp_hdr->checksum = 0;

			uint16_t *data = (uint16_t *) icmp_hdr;
			
			return checksum(data, sizeof(icmphdr)) == original_sum;
		}

	public:
		void handle_arp_packet(char *buff, size_t len, int interface) {
			arp_header *arp_hdr = (arp_header *) (buff + sizeof(ether_header));

			// uint16_t op = ntohs(arp_hdr->op);
			// if (op == ARP_REPLY) {
			// 	cout << "Received ARP reply\n";
			// 	ip_addr_t ip = arp_hdr->spa;
			// 	mac_addr_t mac;
			// 	memcpy(mac.begin(), arp_hdr->sha, 6);
			// 	arp_cache[ip] = mac;
			// 	send_waiting_packets(ip, interface, mac);
			// } else if (op == ARP_REQUEST && arp_hdr->tpa == inet_addr(get_interface_ip(interface))) {
			// 	cout<<"Received ARP request for this router\n";
			// 	send_arp_reply(arp_hdr, interface);
			// }
		}

		void handle_ip_packet(char *buff, size_t len, int interface) {
			cout<<"Received IP packet\n";
			iphdr *ip_hdr = (iphdr *)(buff + sizeof(ether_header));

			if (!crc(ip_hdr)) {
				cout<<"Invalid checksum\nPacket dropped\n";	
				return;
			}

			if (ip_hdr->ttl <= 1) {
				cout<<"TTL expired\nSending ICMP Time Exceeded\n";
				send_icmp_packet(buff, interface, TTL_EXCEEDED);
				return;
			}



			ip_hdr->ttl--;
			ip_addr_t router_ip = inet_addr(get_interface_ip(interface));
			if (memcmp(&ip_hdr->daddr, &router_ip, 4) == 0) {
				send_icmp_packet(buff, interface, ECHO_REPLY);
			} else {
				cout<<"Packet is for another host\n";
				forward_packet(buff, len, interface);
			}
		}

	private:
		void send_waiting_packets(ip_addr_t ip, int interface, mac_addr_t mac) {
			for (auto it = waiting_packets.begin(); it != waiting_packets.end(); ) {
				Packet packet = *it;
				if (packet.dest_ip == ip) {
					packet.add_dest_mac(mac);
					send_packet(packet.interface, packet.buff, packet.len);
					it = waiting_packets.erase(it);
				} else {
					++it;
				}
			}
		}


		void forward_packet(char *buff, size_t len, int interface) {
			ether_header *eth_hdr = (ether_header *) buff;
			iphdr *ip_hdr = (iphdr *)(buff + sizeof(ether_header));
			optional<route_table_entry> next_hop_entry = next_hop(ip_hdr->daddr);

			if (!next_hop_entry.has_value()) {
				cout<<"No route found\nSending ICMP Destination Unreachable\n";
				send_icmp_packet(buff, interface, DEST_UNREACH);
				return;
			}
			
			ip_addr_t next_hop_ip = next_hop_entry->next_hop;
			int next_hop_interface = next_hop_entry->interface;

			// update the ip header
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(iphdr)));


			// update the ethernet header
			eth_hdr->ether_type = htons(ETH_IPV4);
			get_interface_mac(next_hop_interface, eth_hdr->ether_shost);

			// now we need to update the destination mac address
			auto it = arp_cache.find(next_hop_ip);

			if (it == arp_cache.end()) {
				cout << "No entry in ARP cache\n";
				// Packet packet(buff, len, interface, next_hop_ip);
				// waiting_packets.push_back(packet);
				// send_arp_request(next_hop_ip, next_hop_interface);
				// cout << "Sent ARP request\n";
			} else {
				mac_addr_t mac = it->second;
				memcpy(eth_hdr->ether_dhost, mac.begin(), 6);
				cout<<"Forwarding packet to "<<ntohl(next_hop_ip)<<"on interface:"<<next_hop_interface<<endl;
				send_packet(next_hop_interface, buff, len);
			}
		}

		// void send_arp_reply(arp_header *request, int interface) {
		// 	char reply[MAX_PACKET_LEN];
		// 	memset(reply, 0, MAX_PACKET_LEN);

		// 	ether_header *eth_hdr = (ether_header *) reply;
		// 	memcpy(eth_hdr->ether_dhost, request->sha, 6);
		// 	get_interface_mac(interface, eth_hdr->ether_shost);
		// 	eth_hdr->ether_type = htons(ETH_ARP);


		// 	arp_header *arp_hdr = (arp_header *)(reply + sizeof(ether_header));
		// 	arp_hdr->htype = htons(1);
		// 	arp_hdr->ptype = htons(0x800);

		// 	arp_hdr->hlen = 6;
		// 	arp_hdr->plen = 4;

		// 	memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
		// 	memcpy(arp_hdr->tha, request->sha, 6);
		// 	arp_hdr->spa = inet_addr(get_interface_ip(interface));

		// 	arp_hdr->tpa = request->spa;
		// 	arp_hdr->op = htons(ARP_REPLY);

		// 	size_t len = sizeof(ether_header) + sizeof(arp_header);
		// 	send_packet(interface, reply, len);
		// }
			
		// void send_arp_request(ip_addr_t ip, int interface) {
		// 	char request[MAX_PACKET_LEN];
		// 	memset(request, 0, MAX_PACKET_LEN);
		// 	ether_header *eth_hdr = (ether_header *) request;


		// 	// update the ethernet header
		// 	eth_hdr->ether_type = htons(ETH_ARP);
		// 	get_interface_mac(interface, eth_hdr->ether_shost);
		// 	memset(eth_hdr->ether_dhost, MAC_BROADCAST, 6);

		// 	// update the arp header
		// 	arp_header *arp_hdr = (arp_header *)(request + sizeof(ether_header));
		// 	arp_hdr->htype = htons(1);
		// 	arp_hdr->ptype = htons(0x800);

		// 	arp_hdr->hlen = 6;
		// 	arp_hdr->plen = 4;

		// 	// addresses
		// 	memcpy(arp_hdr->sha, eth_hdr->ether_shost, 6);
		// 	memset(arp_hdr->tha, MAC_BROADCAST, 6);
		// 	arp_hdr->spa = inet_addr(get_interface_ip(interface));
		// 	arp_hdr->tpa = ip;

		// 	arp_hdr->op = htons(ARP_REQUEST);

		// 	size_t len = sizeof(ether_header) + sizeof(arp_header);
		// 	send_packet(interface, request, len);
		// }


		void send_packet(int interface, char *buff, size_t len) {
			int sent = 0;

			while (sent < len) {
				int ret = send_to_link(interface, buff + sent, len - sent);
				DIE(ret < 0, "send_to_link");
				sent += ret;
			}
		}

		void send_icmp_packet(char *buff, int interface, uint8_t type) {

			if (type == ECHO_REPLY) {
					send_icmp_echo_reply(buff, interface);
					cout<<"Sent ICMP Echo Reply\n";
			} else {
				send_icmp_failure(buff, interface, type);
				cout << "Sent ICMP Destination Unreachable or ttl exceeded\n";
			}
		}


		void send_icmp_failure(char *buff, int interface, uint8_t type) {

			ether_header *eth_hdr = (ether_header *) buff;
			iphdr *ip_hdr = (iphdr *)(buff + sizeof(ether_header));
			icmphdr *icmp_hdr = (icmphdr *)(buff + sizeof(ether_header) + sizeof(iphdr));

			// copy the icmp payload as the first 64 bits of the ip packet
			char icmp_payload[ICMP_PAYLOAD_SIZE];
			memcpy(icmp_payload, ip_hdr, ICMP_PAYLOAD_SIZE);
			
			// update the ethernet header
			swap(eth_hdr->ether_dhost, eth_hdr->ether_shost);

			// update the ip header
			swap(ip_hdr->daddr, ip_hdr->saddr);
			ip_hdr->ttl = DEFAULT_TTL;
			ip_hdr->protocol = IP_ICMP;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(iphdr)));
			
			// update the icmp header
			icmp_hdr->type = type;
			icmp_hdr->code = 0;
			memcpy(buff + sizeof(ether_header) + sizeof(iphdr) + sizeof(icmphdr), icmp_payload, ICMP_PAYLOAD_SIZE);
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(icmphdr)) + ICMP_PAYLOAD_SIZE);
			
			size_t len = sizeof(ether_header) + 4 * ip_hdr->ihl + ICMP_PAYLOAD_SIZE;
			cout << "Sending ICMP packet failure \n";
			send_packet(interface, buff, len);

			swap(eth_hdr->ether_dhost, eth_hdr->ether_shost);
		}

		void send_icmp_echo_reply(char *buff, int interface) {
			ether_header *eth_hdr = (ether_header *) buff;
			swap(eth_hdr->ether_dhost, eth_hdr->ether_shost);

			iphdr *ip_hdr = (iphdr *)(buff + sizeof(ether_header));
			swap(ip_hdr->saddr, ip_hdr->daddr);
			ip_hdr->ttl = DEFAULT_TTL;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(iphdr)));

			icmphdr *icmp_hdr = (icmphdr *)(buff + sizeof(ether_header) + sizeof(iphdr));
			if (!crc(icmp_hdr)) {
				cout<<"Invalid checksum\nPacket dropped\nICMP drop";	
				return;
			}

			icmp_hdr->type = ECHO_REPLY;
			icmp_hdr->code = 0;
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, ICMP_PACKET_SIZE));

			send_packet(interface, buff, ICMP_PACKET_SIZE);
		}

		// void print_arp_cache() {
		// 	cout<<"ARP Cache\n";
		// 	for (auto it = arp_cache.begin(); it != arp_cache.end(); ++it) {
		// 		cout<<it->first<<" -> ";
		// 		for (int i = 0; i < 6; ++i) {
		// 			cout<<it->second[i];
		// 			if (i < 5) {
		// 				cout<<":";
		// 			}
		// 		} 
		// 		cout<<endl;
		// 	}
		// }
};


int main(int argc, char *argv[])
{
	Router router(argv[1]);
	cout << "Router started\n";

	char buf[MAX_PACKET_LEN];
	size_t len;

	// Do not modify this line
	init(argc - 2, argv + 2);


	while (1) {

		int interface;
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		ether_header *eth_hdr = (ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */
		cout<<"Received packet on interface " << interface << endl;
		if (ntohs(eth_hdr->ether_type) == ETH_IPV4) {
			router.handle_ip_packet(buf, len, interface);
		} else if (ntohs(eth_hdr->ether_type) == ETH_ARP) {
			router.handle_arp_packet(buf, len, interface);
		} else {
			cout<<"Unknown packet type\n" << endl << "Dropping packet\n";
		}
	}
}


