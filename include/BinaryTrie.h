#ifndef BINARYTRIE_H
#define BINARYTRIE_H
#pragma once

#include "Node.h"
#include "lib.h"
#include "protocols.h"
#include "lib_router.h"
#include <optional>
#include <cstdint>

/*inspired from https://opendatastructures.org/ods-java/13_1_BinaryTrie_digital_sea.html*/

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