#ifndef _FILESYS_XATTR_H__
#define _FILESYS_XATTR_H__
#include "DataPack.h"

#define XATTR_INODE_HASH_SIZE 65536
#define XATTR_DATA_HASH_SIZE 524288

class CFsXAttrData
{
public:
    static CFsXAttrData **s_data_hash;
public:
    CFsXAttrData();
    ~CFsXAttrData();

public:
    uint32_t inode;
    uint8_t anleng;
    uint32_t avleng;
    uint8_t *attrname;
    uint8_t *attrvalue;
    CFsXAttrData **previnode,*nextinode;
    CFsXAttrData **prev,*next;

public:
    void release();
    static void xattr_dump();
    static void store_xattr(FILE *fd);
    static inline uint32_t data_hash_fn(uint32_t inode,uint8_t anleng,const uint8_t *attrname);
    static uint8_t getattr(uint32_t inode,uint8_t anleng,const uint8_t *attrname,uint32_t *avleng,uint8_t **attrvalue);
};

class CFsXAttrNode
{
public:
    static CFsXAttrNode **s_inode_hash;
public:
    CFsXAttrNode();
    ~CFsXAttrNode();


    static void xattr_init(void);
    static void release(uint32_t inode);
    static int load_xattr(FILE *fd,int ignoreflag);
    static uint8_t listattr_leng(uint32_t inode,void **xanode,uint32_t *xasize);
    static uint8_t setattr(uint32_t inode,
        uint8_t anleng,const uint8_t *attrname,
        uint32_t avleng,const uint8_t *attrvalue,
        uint8_t mode);
    static inline uint32_t inode_hash_fn(uint32_t inode) {
        return ((inode*0x72B5F387U)&(XATTR_INODE_HASH_SIZE-1));
    }
public:
    uint32_t inode;
    uint32_t anleng;
    uint32_t avleng;
    CFsXAttrData *data_head;
    CFsXAttrNode *next;
};

inline uint32_t CFsXAttrData::data_hash_fn(uint32_t inode,uint8_t anleng,const uint8_t *attrname)
{
    uint32_t hash = inode*5381U;
    while (anleng) {
        hash = (hash * 33U) + (*attrname);
        attrname++;
        anleng--;
    }

    return (hash&(XATTR_DATA_HASH_SIZE-1));
}

#endif
