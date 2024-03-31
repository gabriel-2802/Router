#pragma once

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

#include "lib.h"
#include "protocols.h"
#include "BinaryTrie.h"
#include "Node.h"
#include "lib_router.h"

using namespace std;

class Router {
	private:
		BinaryTrie *routing_table;
		unordered_map<ip_addr_t, mac_addr_t> arp_cache;
		list<Packet> packet_queue;


	public:
		Router(char *file_name);

		~Router();

		void run();

	private:
	 	void build_routes(char *file_name);

		// used initially to build the arp cache from a static file, not used in the final implementation
		void build_static_arp_table(char *file_name, size_t len);

		optional<route_table_entry> next_hop(ip_addr_t ip);

		bool crc(iphdr *ip_hdr);

		bool crc(icmphdr *icmp_hdr);

		void handle_packet(Packet packet);

		void handle_arp_packet(Packet packet);

		void handle_ip_packet(Packet packet);

		void forward_ip_packet(Packet packet);

		void prepare_icmp_header(Packet& packet, uint8_t type);

		void send_arp_reply(Packet packet);

		void send_arp_request(ip_addr_t ip, int interface);
			
		void send_packet(Packet packet);

		void send_icmp_echo_reply(Packet packet);

		void send_queued_packets(ip_addr_t ip, mac_addr_t mac);
};
