#include "FileSysMgr.h"
#include "ChunkCtrl.h"

uint64_t CFileSysMgr::s_MetaVersion = 0;
uint64_t CFileSysMgr::s_trashspace = 0;
uint64_t CFileSysMgr::s_reservedspace = 0;
uint32_t CFileSysMgr::s_trashnodes = 0;
uint32_t CFileSysMgr::s_reservednodes = 0;
uint32_t CFileSysMgr::s_filenodes = 0;
uint32_t CFileSysMgr::s_dirnodes = 0;
uint32_t CFileSysMgr::s_nodes = 0;
uint32_t CFileSysMgr::s_chunks = 0;
uint32_t CFileSysMgr::stats_all[16] = {0};
uint32_t CFileSysMgr::stats_all_chunks[11][11] = {{0}};
uint32_t CFileSysMgr::stats_regular_chunks[11][11] = {{0}};

uint32_t CFileSysMgr::stats_deletions = 0;
uint32_t CFileSysMgr::stats_replications = 0;

CFileSysMgr::CFileSysMgr()
{
    uint32_t i, j;
    for (i=0 ; i<11 ; i++) {
        for (j=0 ; j<11 ; j++) {
            stats_all_chunks[i][j]=0;
            stats_regular_chunks[i][j]=0;
        }
    }
}

CFileSysMgr::~CFileSysMgr()
{
}

CFileSysMgr* CFileSysMgr::getInstance()
{
    static CFileSysMgr s_Instance;
    return &s_Instance;
}

void CFileSysMgr::init()
{

}

void CFileSysMgr::get_stats(uint32_t stats[16]) 
{
    memcpy(stats, stats_all, sizeof(uint32_t) * 16);
    memset(stats_all, 0, sizeof(uint32_t) * 16);
}

#ifndef METARESTORE

void CFileSysMgr::fs_info(uint64_t *totalspace,uint64_t *availspace,
                          uint64_t *trspace,uint32_t *trnodes,
                          uint64_t *respace,uint32_t *renodes,
                          uint32_t *inodes,uint32_t *dnodes,uint32_t *fnodes)
{
    CChunkSvrMgr::getInstance()->get_allspace(totalspace,availspace);

    *trspace = s_trashspace;
    *trnodes = s_trashnodes;
    *respace = s_reservedspace;
    *renodes = s_reservednodes;
    *inodes = s_nodes;
    *dnodes = s_dirnodes;
    *fnodes = s_filenodes;
}

#endif

void chunk_state_change(uint8_t oldgoal,uint8_t newgoal,
                        uint8_t oldavc,uint8_t newavc,
                        uint8_t oldrvc,uint8_t newrvc)
{
#define CHECK_MAX_LIMIT(n) if(n>9){n=10;}

    CHECK_MAX_LIMIT(oldgoal);
    CHECK_MAX_LIMIT(newgoal);
    CHECK_MAX_LIMIT(oldavc);
    CHECK_MAX_LIMIT(newavc);
    CHECK_MAX_LIMIT(oldrvc);
    CHECK_MAX_LIMIT(newrvc);

    CFileSysMgr::stats_all_chunks[oldgoal][oldavc]--;
    CFileSysMgr::stats_all_chunks[newgoal][newavc]++;
    CFileSysMgr::stats_regular_chunks[oldgoal][oldrvc]--;
    CFileSysMgr::stats_regular_chunks[newgoal][newrvc]++;
}


void CFileSysMgr::chunk_stats(uint32_t *del,uint32_t *repl)
{
    *del = stats_deletions;
    *repl = stats_replications;
    stats_deletions = 0;
    stats_replications = 0;
}

void CFileSysMgr::chunk_info(uint32_t *allChunks,uint32_t *allCopies,uint32_t *rValidCopies)
{
    uint32_t i,j,ag,rg;
    *allChunks = CFileSysMgr::s_chunks;
    *allCopies = 0;
    *rValidCopies = 0;

    for (i=1 ; i<=10 ; i++)
    {
        ag=rg=0;
        for (j=0 ; j<=10 ; j++) {
            ag += stats_all_chunks[j][i];
            rg += stats_regular_chunks[j][i];
        }

        *allCopies += ag*i;
        *rValidCopies += rg*i;
    }
}

uint32_t CFileSysMgr::get_chunks_missing_count()
{
    uint32_t res=0;
    for (uint8_t i=1 ; i<=10 ; i++) {
        res+=stats_all_chunks[i][0];
    }

    return res;
}

void CFileSysMgr::get_store_chunks_counters(uint8_t *buff, uint8_t matrixid)
{
    uint8_t i,j;
    if (matrixid==0) {
        for (i=0 ; i<=10 ; i++) {
            for (j=0 ; j<=10 ; j++) {
                put32bit(&buff, stats_all_chunks[i][j]);
            }
        }
    } else if (matrixid==1) {
        for (i=0 ; i<=10 ; i++) {
            for (j=0 ; j<=10 ; j++) {
                put32bit(&buff, stats_regular_chunks[i][j]);
            }
        }
    } else {
        memset(buff,0,11*11*4);
    }
}

