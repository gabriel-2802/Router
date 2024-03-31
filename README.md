
# Router Project Overview


## Structure

- **`include/`:** Contains all the header files necessary for the project.
    - `protocols.h`: structs related to the Ethernet, IPv4, ICMP, and ARP protocols.
    - `lib.h`: Helper functions provided for the project.
    - `Node.h`: Defines the node structure used in the Trie for route storage.
    - `Router.h`: The main class of the program, encapsulating router logic.
    - `BinaryTrie.h`: Implements the tree structure used for the routing table.
    - `lib_router.h`: Contains useful macro definitions and the packet class.

- **`lib/`:** Stores `.cpp` files with implementations for the Node, BinaryTrie, and Router classes.

- **`main.cpp`:** The entry point of the program. Instantiates and runs the Router class.

## Development

- **Protocol Implementation:** The Router supports Ethernet, IPv4, ICMP, and ARP protocols

- **Routing Table Initialization:** When the Router is first instantiated,  IT builds a Trie from a file containing routing table entries, with keys as binary representations of IP prefixes for efficient storage.

- **Trie Structure:** Inspired by https://opendatastructures.org/ods-java/13_1_BinaryTrie_digital_sea.html,  each node in the Trie has 2 children: left (0) and right (1)

- **ARP Cache:** The Router's `arp_cache` is implemented by using a map for quick (O(1)) lookups of MAC addresses based on IP keys.

- **Packet Queueing:** If a MAC address is not found in `arp_cache`, the router sends an ARP request and queues the packet in a linked list, allowing for O(1) addition and removal time

- **ARP Request Handling:** The Router saves sender MAC and IP addresses from ARP requests not addressed to it, for future use.

- **Longest Prefix Match (LPM) Algorithm:** Implemented using the binary Trie to achieve efficient O(key_length) lookups.

- **Unused ARP Table Loading:** The Router supports loading an ARP table into memory, however this functionality is not used in the final project

- **IP Packet Processing:**  For each ip packet received, the router checks and decrements the `TTL` and sends `ICMP` packets in case of hosts unreachable or time exceeded


