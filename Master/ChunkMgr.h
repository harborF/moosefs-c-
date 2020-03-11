#ifndef _CHUNK_MGR_H__
#define _CHUNK_MGR_H__
#include <time.h>
#include "DataPack.h"
#include "ChunkObj.h"
#include "FileSysMgr.h"

#define CHUNKFSIZE 16
#define CHUNKCNT 1000
#define HASHSIZE 0x100000
#define HASHPOS(chunkid) (((uint32_t)chunkid)&0xFFFFF)

#define UNUSED_DELETE_TIMEOUT (86400*7)

class CChunkMgr
{
public:
    static uint64_t s_nextchunkid;
    static CChunkObj *s_chunkhash[HASHSIZE];

protected:
    CChunkMgr();
public:
    ~CChunkMgr();
public:
    static CChunkMgr* getInstance();
    void clear();
    void chunk_dump(void);

#ifndef METARESTORE
    void chunk_server_disconnected(void *ptr);
    void chunk_damaged(void *ptr,uint64_t chunkid);
    void chunk_lost(void *ptr,uint64_t chunkid);
    /* ---- */
    void chunk_server_has_chunk(void *ptr,uint64_t chunkid,uint32_t version);
    void got_delete_status(void *ptr,uint64_t chunkid,uint8_t status);
    void got_replicate_status(void *ptr,uint64_t chunkid,uint32_t version,uint8_t status);
    void got_chunkop_status(void *ptr,uint64_t chunkid,uint8_t status);
#endif

public:
    static void chunk_newfs(void);
    static int chunk_load(FILE *fd);
    static void chunk_store(FILE *fd);

public:
    uint32_t chunk_count(void);
    CChunkObj* chunk_new();
    CChunkObj* chunk_new(uint64_t chunkid);
    CChunkObj* chunk_find(uint64_t chunkid);
    void chunk_delete(CChunkObj* c);

public:
    int chunk_change_file(uint64_t chunkid,uint8_t prevgoal,uint8_t newgoal);
    int chunk_delete_file(uint64_t chunkid,uint8_t goal);
    int chunk_add_file(uint64_t chunkid,uint8_t goal);
    int chunk_unlock(uint64_t chunkid);
#ifndef METARESTORE
    int chunk_get_validcopies(uint64_t chunkid,uint8_t *vcopies);
#endif
    int chunk_set_version(uint64_t chunkid,uint32_t version);
    int chunk_increase_version(uint64_t chunkid);
};

#define ChkMgr CChunkMgr::getInstance()

#define chunk_got_create_status CChunkMgr::getInstance()->got_chunkop_status
#define chunk_got_duplicate_status CChunkMgr::getInstance()->got_chunkop_status
#define chunk_got_setversion_status CChunkMgr::getInstance()->got_chunkop_status
#define chunk_got_truncate_status CChunkMgr::getInstance()->got_chunkop_status
#define chunk_got_duptrunc_status CChunkMgr::getInstance()->got_chunkop_status

#endif
