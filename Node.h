
#ifndef NODE_H
#define NODE_H
#pragma once

#include "include/lib.h"

class Node {
public:
    bool isLeaf; // true if the node is a leaf, therefore a valid ip address
    route_table_entry entry;
    Node *left, *right; // left is 0, right is 1

    Node(); 
    Node(route_table_entry entry); 
    ~Node();
};

#endif // NODE_H
