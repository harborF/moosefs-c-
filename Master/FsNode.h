#ifndef _FILESYS_NODE_H__
#define _FILESYS_NODE_H__
#include "DataPack.h"
#include "mfsFactory.h"
#ifndef METARESTORE
#include "ServerCore.h"
#include "changelog.h"
#include "DCacheMgr.h"
#endif

#define MFS_ROOT_ID 1
#define DEFAULT_GOAL 1
#define MAXFNAMELENG 255
#define DEFAULT_TRASHTIME 86400

#define NODEHASHBITS (22)
#define NODEHASHSIZE (1<<NODEHASHBITS)
#define NODEHASHPOS(nodeid) ((nodeid)&(NODEHASHSIZE-1))

#ifndef METARESTORE
typedef struct _statsrecord {
    uint32_t inodes;
    uint32_t dirs;
    uint32_t files;
    uint32_t chunks;
    uint64_t length;
    uint64_t size;
    uint64_t realsize;
} STStatsRec;
#endif

class CFsEdge;
class CFsQuota;
class CFsNode
{
public:
    static CFsNode *s_root;
    static CFsNode* s_nodehash[NODEHASHSIZE];
public:
    uint32_t id;
    uint32_t ctime,mtime,atime;
    uint8_t type, goal;
    uint16_t mode;	// only 12 lowest bits are used for mode, in unix standard upper 4 are used for object type, but since there is field "type" this bits can be used as extra flags
    uint32_t uid, gid;
    uint32_t trashtime;
    union _data {
        struct _ddata {				// type==TYPE_DIRECTORY
            CFsEdge *children;
            uint32_t nlink;
            uint32_t elements;
#ifndef METARESTORE
            STStatsRec *stats;
#endif
            CFsQuota *quota;
        } ddata;
        struct _sdata {				// type==TYPE_SYMLINK
            uint32_t pleng;
            uint8_t *path;
        } sdata;
        struct _devdata {
            uint32_t rdev;			// type==TYPE_BLOCKDEV ; type==TYPE_CHARDEV
        } devdata;
        struct _fdata {				// type==TYPE_FILE ; type==TYPE_TRASH ; type==TYPE_RESERVED
            uint64_t length;
            uint64_t *chunktab;
            uint32_t chunks;
            STSIDRec *sessIDs;
        } fdata;
    } data;
    CFsEdge *parents;
    CFsNode *next;

public:
    void dump();
#ifndef METARESTORE
    void checkfile(uint32_t chunkcount[11]);
    void get_stats(STStatsRec *sr);
    void sub_stats(STStatsRec *sr);
    void add_stats(STStatsRec *sr);
    void add_sub_stats(STStatsRec *newsr,STStatsRec *prevsr);
#endif
    uint32_t getdir_size(uint8_t withattr);
    static uint32_t getdirpath_size(uint32_t inode);
    static void getdirpath_data(uint32_t inode,uint8_t *buff,uint32_t size);
    void changefilegoal(uint8_t g);

    void set_length(uint64_t length);
    uint8_t nameisused(uint16_t nleng,const uint8_t *name);
    CFsEdge* lookup(uint16_t nleng,const uint8_t *name);

    static void dumpnodes();
    static CFsNode* id_to_node(uint32_t id);
    static char* escape_name(uint32_t nleng, const uint8_t *name);
    static int name_check(uint32_t nleng,const uint8_t *name);

    CFsQuota* new_quotanode();
    void delete_quotanode();
    uint8_t test_quota();

    void release_node(uint32_t ts);
    static CFsNode* create_node(uint32_t ts,CFsNode* node,
        uint16_t nleng,const uint8_t *name,
        uint8_t type,uint16_t mode,
        uint32_t uid,uint32_t gid,uint8_t copysgid);

    static void link_edge(uint32_t ts,
        CFsNode *parent,CFsNode *child,
        uint16_t nleng,const uint8_t *name);
    static void unlink_edge(uint32_t ts,CFsEdge *e);

    static inline uint32_t fsnodes_hash(uint32_t parentid,uint16_t nleng,const uint8_t *name) 
    {
        uint32_t hash,i;
        hash = ((parentid * 0x5F2318BD) + nleng);
        for (i=0 ; i<nleng ; i++) {
            hash = hash*33+name[i];
        }
        return hash;
    };
};

#endif
