#ifndef _FILESYS_MGR_H__
#define _FILESYS_MGR_H__
#include "FsNode.h"
#include "FsEdge.h"
#include "FsQuota.h"
#include "FsXAttr.h"

class CFileSysMgr
{
public:
    static uint64_t s_MetaVersion;
    static uint64_t s_trashspace;
    static uint64_t s_reservedspace;
    static uint32_t s_trashnodes;
    static uint32_t s_reservednodes;
    static uint32_t s_filenodes;
    static uint32_t s_dirnodes;
    static uint32_t s_nodes;
    static uint32_t s_chunks;

    static uint32_t stats_all[16];
    static uint32_t stats_all_chunks[11][11];
    static uint32_t stats_regular_chunks[11][11];
    static uint32_t stats_deletions;
    static uint32_t stats_replications;
protected:
    CFileSysMgr();
public:
    ~CFileSysMgr();
    static CFileSysMgr* getInstance();
    void init();
public:
    static void get_stats(uint32_t stats[16]);
#ifndef METARESTORE
    static void fs_info(uint64_t *totalspace,uint64_t *availspace,
        uint64_t *trspace,uint32_t *trnodes,
        uint64_t *respace,uint32_t *renodes,
        uint32_t *inodes,uint32_t *dnodes,uint32_t *fnodes);
#endif
    static void chunk_stats(uint32_t *del,uint32_t *repl);
    static void chunk_info(uint32_t *allChunks,uint32_t *allCopies,uint32_t *rValidCopies);
    static uint32_t get_chunks_missing_count(void);
    static void get_store_chunks_counters(uint8_t *buff,uint8_t matrixid);
};

void chunk_state_change(uint8_t oldgoal,uint8_t newgoal,
                        uint8_t oldavc,uint8_t newavc,
                        uint8_t oldrvc,uint8_t newrvc);

#endif
