#ifndef _MFS_FACTORY_H__
#define _MFS_FACTORY_H__
#include "config.h"
#include "DataPack.h"
#include "ChunkObj.h"

#define USE_FREENODE_BUCKETS 1
#define USE_CUIDREC_BUCKETS 1
#define USE_SLIST_BUCKETS 1
#define USE_FLIST_BUCKETS 1
#define USE_CHUNK_BUCKETS 1

template<typename T, int TMax>
class TEntryBucket
{
    typedef struct _T_bucket {
        T bucket[TMax];
        uint32_t firstfree;
        struct _T_bucket *next;
    } T_bucket;
public:
    TEntryBucket();
    ~TEntryBucket();

    T* newT();
    void freeT(T*);
    void freeAll();
private:
    T_bucket *tbhead;
    T *tfreehead;
};

//////////////////////////////////////////////////////////////////////////

typedef struct _sidrec {
    uint32_t sessionid;
    struct _sidrec *next;
} STSIDRec;

STSIDRec* sessionidrec_malloc();
void sessionidrec_free(STSIDRec* p);

typedef struct _freenode {
    uint32_t id;
    uint32_t ftime;
    struct _freenode *next;
} STFreeNode;

STFreeNode* freenode_malloc();
void freenode_free(STFreeNode* p);

#ifndef METARESTORE

slist* slist_malloc();
void slist_free(slist* p);

#endif 

CChunkObj* chunk_malloc();
void chunk_free(CChunkObj* p);

#endif
