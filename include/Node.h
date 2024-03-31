
#ifndef NODE_H
#define NODE_H
#pragma once

#include "lib.h"

class Node {
public:
    route_table_entry entry;
    bool isLeaf; // true if the node is a leaf, therefore a valid ip address
    Node *left, *right; // left is 0, right is 1

    Node(); 
    Node(route_table_entry entry); 
    ~Node();
};

#endif // NODE_H
