#include "BinaryTrie.h"
#include "router_lib.h"
#include <arpa/inet.h>

using namespace std;


BinaryTrie::BinaryTrie()
{
	root = new Node();
}

BinaryTrie::~BinaryTrie()
{
	delete root;
}

void BinaryTrie::insert(route_table_entry entry)
{
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

optional<route_table_entry> BinaryTrie::longest_prefix_match(ip_addr_t ip)
{
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

int BinaryTrie::bit_count(uint32_t n) {
    int count = 0;
    while (n) {
        count += n & 1;
        n >>= 1;
    }
    return count;
}