
#include "include/lib.h"
#include "include/protocols.h"
#include "BinaryTrie.h"
#include "Node.h"
#include "lib_router.h"


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
		list<Packet> packet_queue;


	public:
		Router(char *file_name) {
			routing_table = new BinaryTrie();
			build_routes(file_name);
		}

		~Router() {
			delete routing_table;
		}

		void run() {
			while (1) {
				Packet packet;
				packet.interface = recv_from_any_link(packet.buff, &packet.len);
				DIE (packet.interface < 0, "recv_from_any_link");

				cout << "handle_packet\n";
				handle_packet(packet);
			}
		}

	private:
	 	void build_routes(char *file_name) {
			routing_table = new BinaryTrie();
			route_table_entry *entries = new route_table_entry[MAX_RTABLE_SIZE];
			int len = read_rtable(file_name, entries);

			for (int i = 0; i < len; ++i) {
				route_table_entry *entry = entries + i;
				if ((entry->prefix & entry->mask )== entry->prefix) {
					routing_table->insert(*entry);
				}
			}

			delete[] entries;
		}


		// used initially to build the arp cache from a static file, not used in the final implementation
		void build_static_arp_table(char *file_name, size_t len) {
			arp_table_entry arp_table[len];
			parse_arp_table(file_name, arp_table);

			for (int i = 0; i < 6; ++i) {
				arp_table_entry entry = arp_table[i];
				mac_addr_t mac_addr;
				memcpy(mac_addr.begin(), entry.mac, 6);

				arp_cache[entry.ip] = mac_addr;
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

	private:
		void handle_packet(Packet packet) {
			ether_header *eth_hdr = (ether_header *) packet.buff;
			if (ntohs(eth_hdr->ether_type) == ETH_IPV4) {
				handle_ip_packet(packet);

			} else if (ntohs(eth_hdr->ether_type) == ETH_ARP) {
				handle_arp_packet(packet);

			} else {
				cout<<"Unknown packet type\n" << endl << "Dropping packet\n";
			}
		}


		void handle_arp_packet(Packet packet) {
			arp_header *arp_hdr = (arp_header *)(packet.buff + sizeof(ether_header));
			uint16_t op = ntohs(arp_hdr->op);

			if (op == ARP_REQUEST) {
				cout<<"Received ARP Request\n";
				send_arp_reply(packet);
			} else if (op == ARP_REPLY) {
				cout<<"Received ARP Reply\n";
				mac_addr_t mac;
				memcpy(mac.begin(), arp_hdr->sha, 6);
				arp_cache[arp_hdr->spa] = mac;
				send_queued_packets(arp_hdr->spa, mac);
			}
		}

		void handle_ip_packet(Packet packet) {
			cout<<"Received IP packet\n";
			iphdr *ip_hdr = (iphdr *)(packet.buff + sizeof(ether_header));
			ip_addr_t router_ip = inet_addr(get_interface_ip(packet.interface));

			if (memcmp(&ip_hdr->daddr, &router_ip, 4) == 0) {
				cout<<"Packet is for this router\n Sending ICMP Echo Reply\n";
				send_icmp_echo_reply(packet);
			} else {
				cout<<"Packet is for another host\n";
				forward_ip_packet(packet);
			}
		}

		void forward_ip_packet(Packet packet) {
			iphdr *ip_hdr = (iphdr *)(packet.buff + sizeof(ether_header));

			if (!crc(ip_hdr)) {
				cout<<"Invalid checksum\nPacket dropped\n";	
				return;
			}

			optional<route_table_entry> route = next_hop(ip_hdr->daddr);

			if (!route.has_value()) {
				cout<<"No route found\nSending ICMP Destination Unreachable\n";
				prepare_icmp_header(packet, DEST_UNREACH);
			}

			if (ip_hdr->ttl <= 1) {
				cout<<"TTL expired\nSending ICMP Time Exceeded\n";
				prepare_icmp_header(packet, TTL_EXCEEDED);
			}

			ip_addr_t next_hop_ip = route->next_hop;
			int next_hop_interface = route->interface;
			packet.interface = next_hop_interface;

			// update the ip header
			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(iphdr)));

			// update the ethernet header
			ether_header *eth_hdr = (ether_header *) packet.buff;
			eth_hdr->ether_type = htons(ETH_IPV4);
			get_interface_mac(next_hop_interface, eth_hdr->ether_shost);

			// now we need to find the destination mac address associated with the next_hop_ip
			auto it = arp_cache.find(next_hop_ip);

			if (it == arp_cache.end()) {
				cout << "No entry in ARP cache - Fatal error - Packet dropped\n";
				packet.dest_ip = next_hop_ip;
				packet_queue.push_back(packet);
				send_arp_request(next_hop_ip, next_hop_interface);
			} else {
				mac_addr_t mac = it->second;
				memcpy(eth_hdr->ether_dhost, mac.begin(), 6);
				cout<<"Forwarding packet to "<<ntohl(next_hop_ip)<<" on interface:"<<next_hop_interface<<endl;
				send_packet(packet);
			}
		}


		void prepare_icmp_header(Packet& packet, uint8_t type) {
			cout<<"Preparing ICMP error header\n";

			iphdr *ip_hdr = (iphdr *)(packet.buff + sizeof(ether_header));
			icmphdr *icmp_hdr = (icmphdr *)(packet.buff + sizeof(ether_header) + sizeof(iphdr));
			packet.len = sizeof(ether_header) + 4 * ip_hdr->ihl + ICMP_PAYLOAD_SIZE;

			// the payload of the icmp packet is the first 64 bits of the ip packet
			char icmp_payload[ICMP_PAYLOAD_SIZE];
			memcpy(icmp_payload, ip_hdr, ICMP_PAYLOAD_SIZE); 

			icmp_hdr->type = type;
			icmp_hdr->code = 0;
			memcpy(packet.buff + sizeof(ether_header) + sizeof(iphdr) + sizeof(icmphdr), icmp_payload, ICMP_PAYLOAD_SIZE);
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(icmphdr)) + ICMP_PAYLOAD_SIZE);

			// ip header update since we send it back, not forward it
			swap(ip_hdr->saddr, ip_hdr->daddr);
			ip_hdr->ttl = DEFAULT_TTL;
			ip_hdr->tot_len = htons(sizeof(iphdr) + sizeof(icmphdr) + ICMP_PAYLOAD_SIZE);
			ip_hdr->protocol = IP_ICMP;
		}

		void send_queued_packets(ip_addr_t ip, mac_addr_t mac) {
			for (auto it = packet_queue.begin(); it != packet_queue.end();) {
				Packet packet = *it;
				if (packet.dest_ip == ip) {
					packet.add_dest_mac_to_packet(mac);
					send_packet(packet);
					it = packet_queue.erase(it);
				} else {
					++it; // increment the iterator only if we don't erase the current element
				}
			}
		}

		void send_arp_reply(Packet packet) {
			arp_header *arp_hdr = (arp_header *)(packet.buff + sizeof(ether_header));

			ip_addr_t router_ip = inet_addr(get_interface_ip(packet.interface));

			if (arp_hdr->tpa != router_ip) {
				cout<<"ARP packet not for this router - Dropping \n";
				return;
			} 
	
			// the arp request is for this router, therefore we reply
			// update the ethernet header
			ether_header *eth_hdr = (ether_header *) packet.buff;
			memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
			get_interface_mac(packet.interface, eth_hdr->ether_shost);
			eth_hdr->ether_type = htons(ETH_ARP);

			// since we have the mac address of the sender, we can
			// add it to the arp cache
			mac_addr_t aux_mac;
			memcpy(aux_mac.begin(), arp_hdr->sha, 6);
			arp_cache[arp_hdr->spa] = aux_mac;


			// update the arp header
			arp_hdr->op = htons(ARP_REPLY);
			memcpy(arp_hdr->tha, arp_hdr->sha, 6);
			get_interface_mac(packet.interface, arp_hdr->sha);

			// swap the sender and target ip addresses
			ip_addr_t aux_ip = arp_hdr->spa;
			arp_hdr->spa = arp_hdr->tpa;
			arp_hdr->tpa = aux_ip;

			packet.len = sizeof(ether_header) + sizeof(arp_header);
			send_packet(packet);
		}

		void send_arp_request(ip_addr_t ip, int interface) {
			Packet packet;

			// create the ethernet header
			ether_header *eth_hdr = (ether_header *) packet.buff;
			eth_hdr->ether_type = htons(ETH_ARP);
			get_interface_mac(interface, eth_hdr->ether_shost);
			memset(eth_hdr->ether_dhost, MAC_BROADCAST, 6);


			// create the arp header
			arp_header *arp_hdr = (arp_header *)(packet.buff + sizeof(ether_header));
			arp_hdr->htype = htons(1);
			arp_hdr->ptype = htons(0x0800);
			arp_hdr->hlen = 6;
			arp_hdr->plen = 4;
			arp_hdr->op = htons(ARP_REQUEST);
			get_interface_mac(interface, arp_hdr->sha);
			memset(arp_hdr->tha, MAC_BROADCAST, 6);
			arp_hdr->spa = inet_addr(get_interface_ip(interface));
			arp_hdr->tpa = ip;


			packet.len = sizeof(ether_header) + sizeof(arp_header);
			packet.interface = interface;
			send_packet(packet);
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
			



		void send_packet(Packet packet) {
			size_t sent = 0;

			while (sent < packet.len) {
				int ret = send_to_link(packet.interface, packet.buff + sent, packet.len - sent);
				DIE(ret < 0, "send_to_link");
				sent += ret;
			}
		}

		void send_icmp_echo_reply(Packet packet) {

			// update the ethernet header by swapping the source and destination mac addresses
			ether_header *eth_hdr = (ether_header *) packet.buff;
			swap(eth_hdr->ether_dhost, eth_hdr->ether_shost);
			
			// update the ip header by swapping the source and destination ip addresses
			iphdr *ip_hdr = (iphdr *)(packet.buff + sizeof(ether_header));
			if (!crc(ip_hdr)) {
				cout<<"Invalid ip checksum\nPacket dropped\n";	
				return;
			}
			swap(ip_hdr->saddr, ip_hdr->daddr);
			ip_hdr->ttl = DEFAULT_TTL;
			ip_hdr->check = 0;
			ip_hdr->check = htons(checksum((uint16_t *) ip_hdr, sizeof(iphdr)));


			// build the icmp header
			icmphdr *icmp_hdr = (icmphdr *)(packet.buff + sizeof(ether_header) + sizeof(iphdr));
			if (!crc(icmp_hdr)) {
				cout<<"Invalid icmp checksum\nPacket dropped\nICMP drop";	
				return;
			}

			icmp_hdr->type = ECHO_REPLY;
			icmp_hdr->code = 0;
			icmp_hdr->checksum = 0;
			icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, ICMP_PACKET_SIZE));

			packet.len = ICMP_PACKET_SIZE;

			send_packet(packet);
		}
};


int main(int argc, char *argv[])
{
	Router *router = new Router(argv[1]);

	init(argc - 2, argv + 2);
	router->run();
	delete router;
}


