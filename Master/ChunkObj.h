#ifndef _CHUNK_OBJ_H__
#define _CHUNK_OBJ_H__
#include "DataPack.h"

/* slist.valid */
/* INVALID - wrong version / or got info from chunkserver (IO error etc.)  ->  to delete */
/* DEL - deletion in progress */
/* BUSY - operation in progress */
/* VALID - ok */
/* TDBUSY - to delete + BUSY */
/* TDVALID - want to be deleted */
enum {INVALID,DEL,BUSY,VALID,TDBUSY,TDVALID};
/* CChunkObj.operation */
enum {NONE,CREATE,SET_VERSION,DUPLICATE,TRUNCATE,DUPTRUNC};

#ifndef METARESTORE

typedef struct _slist {
    void *ptr;
    uint8_t valid;
    uint32_t version;
    struct _slist *next;
} slist;

#endif 

#if 0
typedef struct _flist {
    uint32_t inode;
    uint16_t indx;
    uint8_t goal;
    struct _flist *next;
} flist;
#endif

class CChunkObj
{
public:
    uint64_t chunkid;
    uint32_t version;
    uint8_t goal;
#ifndef METARESTORE
    uint8_t allValidCopies;
    uint8_t rValidCopies;  //regulator
    unsigned bIncVer:1;
    unsigned bInterrupted:1;
    unsigned operation:4;
    slist *slisthead;
#endif  
    uint32_t lockedto;
    uint32_t fcount;
    uint32_t *ftab;
    CChunkObj *next;

public:
    void clear();
public:
    int delete_file_int(uint8_t goal);
    int add_file_int(uint8_t goal);
    int change_file(uint8_t prevgoal,uint8_t newgoal);

#ifndef METARESTORE
    void emergency_increase_version();
    void opr_status(uint8_t status,void *ptr);

    void chunk_lost(void *ptr);
    void damaged(void *ptr);
    void delete_status(void *ptr);
    void disconnected(void *ptr);
    void has_svr_ver(void *ptr,uint32_t version);
#endif
};

#endif