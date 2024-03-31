#include "Node.h"


Node::Node()
{
    isLeaf = false;
    left = right = NULL;
}


Node::Node(route_table_entry entry): entry(entry), isLeaf(true), left(NULL), right(NULL)
{
    
}

Node::~Node()
{
    if (left != NULL) {
        delete left;
        left = NULL;
    }

    if (right != NULL) {
        delete right;
        right = NULL;
    }
}
