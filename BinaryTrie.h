#ifndef BINARYTRIE_H
#define BINARYTRIE_H
#pragma once

#include "Node.h"
#include "include/lib.h"
#include "include/protocols.h"
#include "router_lib.h"
#include <optional>
#include <cstdint>

class BinaryTrie {
public:
    BinaryTrie();
    ~BinaryTrie();
    void insert(route_table_entry entry);
    std::optional<route_table_entry> longest_prefix_match(ip_addr_t ip);

private:
    Node *root;
    int bit_count(uint32_t n);
};

#endif