
#include "include/lib.h"
#include "include/protocols.h"
#include <iostream>
#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include <optional>
#include <unordered_map>
#include <cstring>	
#include <algorithm>
#include <array>

using namespace std;


enum icmp_types {
	ECHO_REPLY = 0,
	DEST_UNREACH = 3,
	TTL_EXCEEDED = 11,
	ECHO_REQUEST = 8
};

enum icmp_codes {

};

typedef array<uint8_t, 6> mac_addr_t;

class Node {
	public:
		bool isLeaf; // true if the node is a leaf, therefore a valid ip address
		route_table_entry entry;
		Node *left, *right; // left is 0, right is 1
		Node() {
			isLeaf = false;
			left = right = NULL;
		}

		Node(route_table_entry entry) {
			isLeaf = true;
			this->entry = entry;
			left = right = NULL;
		}

		~Node() {
			if (left != NULL) {
				delete left;
			} 

			if (right != NULL) {
				delete right;
			}
		}
};


class BinaryTrie {
	public:
		Node *root;
		BinaryTrie() {
			root = new Node();
		}

		~BinaryTrie() {
			delete root;

		}

		void insert(route_table_entry entry) {
			// convert to host order
			ip_addr_t ip_key = ntohl(entry.prefix & entry.mask);

			Node *current = root;
			for (int i = 0; i < bit_count(entry.mask); ++i) {
				uint32_t bit = (ip_key >> (31 - i)) & 1;
				if (bit == 0) {
					if (current->left == NULL) {
						current->left = new Node();
					}
					current = current->left;
				} else {
					if (current->right == NULL) {
						current->right = new Node();
					}
					current = current->right;
				}
			}

			current->isLeaf = true;
			current->entry = entry;
		}

		optional<route_table_entry> longest_prefix_match(ip_addr_t ip) {
			ip_addr_t masked_ip = ntohl(ip);
			Node *current = root;
			route_table_entry best_match;
			bool found = false;
	
			for (int i = 0; i < 32; ++i) {
				if (current->isLeaf) {
					best_match = current->entry;
					found = true;
				}

				uint32_t bit = (masked_ip >> (31 - i)) & 1;
				if (bit == 0) {
					if (current->left == NULL) {
						break;
					}
					current = current->left;
				} else {
					if (current->right == NULL) {
						break;
					}
					current = current->right;
				}
			}

			if (found) {
				return best_match;
			} else {
				return nullopt;
			}
		}

	private:
	 	int bit_count(uint32_t n) {
			int count = 0;
			while (n) {
				count += n & 1;
				n >>= 1;
			}
			return count;
		}
};



BinaryTrie *build_routes(char *file_name) {
	BinaryTrie *trie = new BinaryTrie();
	route_table_entry *entries = new route_table_entry[MAX_RTABLE_SIZE];
	int len = read_rtable(file_name, entries);

	int valid = 0;
	for (int i = 0; i < len; ++i) {
		route_table_entry *entry = entries + i;
		if ((entry->prefix & entry->mask )== entry->prefix) {
			trie->insert(*entry);
		}
	}

	return trie;
}

class Router {
	private:
		BinaryTrie *routing_table;
		unordered_map<ip_addr_t, mac_addr_t> arp_cache;


	public:
		Router(char *file_name) {
			routing_table = new BinaryTrie();
			build_routes(file_name);
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

	public:
		void handle_arp_packet(char *buff, size_t len, int interface) {
			arp_header *arp_hdr = (arp_header *) buff;
			cout<<"to be done\n";

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
				send_icmp_packet(buff, len, interface, TTL_EXCEEDED, 0);
				return;
			}

			ip_hdr->ttl--;
			ip_addr_t router_ip = inet_addr(get_interface_ip(interface));
			if (memcmp(&ip_hdr->daddr, &router_ip, 4) == 0) {
				send_icmp_packet(buff, len, interface, ECHO_REPLY, 0);
			} else {
				cout<<"Packet is for another host\n";
				forward_packet(buff, len, interface);
			}
		}

		void forward_packet(char *buff, size_t len, int interface) {
			ether_header *eth_hdr = (ether_header *) buff;
			iphdr *ip_hdr = (iphdr *)(buff + sizeof(ether_header));
			optional<route_table_entry> next_hop_entry = next_hop(ip_hdr->daddr);

			if (!next_hop_entry.has_value()) {
				cout<<"No route found\nSending ICMP Destination Unreachable\n";
				send_icmp_packet(buff, len, interface, DEST_UNREACH, 0);
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
			} else {
				mac_addr_t mac = it->second;
				memcpy(eth_hdr->ether_dhost, mac.begin(), 6);
				cout<<"Forwarding packet to "<<ntohl(next_hop_ip)<<"on interface:"<<next_hop_interface<<endl;
				send_packet(next_hop_interface, buff, len);
			}
		}


		void send_packet(int interface, char *buff, size_t len) {
			int sent = 0;

			while (sent < len) {
				int ret = send_to_link(interface, buff + sent, len - sent);
				DIE(ret < 0, "send_to_link");
				sent += ret;
			}
		}

		void send_icmp_packet(char *buff, size_t len, int interface, uint8_t type, uint8_t code) {

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

