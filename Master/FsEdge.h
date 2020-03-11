#ifndef _FILESYS_EDGE_H__
#define _FILESYS_EDGE_H__
#include "DataPack.h"

#define EDGEHASH 1

#ifdef EDGEHASH
#define EDGEHASHBITS (22)
#define EDGEHASHSIZE (1<<EDGEHASHBITS)
#define EDGEHASHPOS(hash) ((hash)&(EDGEHASHSIZE-1))
#define LOOKUPNOHASHLIMIT 10
#endif

class CFsNode;
class CFsEdge
{
public:
    static CFsEdge *s_trash;
    static CFsEdge *s_reserved;
    static CFsEdge* s_edgehash[EDGEHASHSIZE];
public:
    CFsEdge();
    ~CFsEdge();

public:
    CFsNode *child,*parent;
    CFsEdge *nextChild,*nextParent;
    CFsEdge **prevChild,**prevParent;
#ifdef EDGEHASH
    CFsEdge *next,**prev;
#endif
    uint16_t nleng;
    uint8_t *name;

public:
    void dump();
    static CFsEdge* new_edge(uint8_t type, uint32_t pleng, uint8_t *path, CFsNode* pChild);
    static CFsEdge* new_edge(CFsNode *parent,CFsNode *child,uint16_t nleng,const uint8_t *name);
    void remove_edge(uint32_t ts);

    uint32_t get_path_size();
    void get_path(uint16_t *pleng,uint8_t **path);
    void get_path_data(uint8_t *path,uint32_t size);

    uint32_t get_detached_size();
    void get_detached_data(uint8_t *dbuff);
};

#endif