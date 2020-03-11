#include "ChunkMgr.h"

int CChunkMgr::chunk_change_file(uint64_t chunkid,uint8_t prevgoal,uint8_t newgoal)
{
    if (prevgoal==newgoal) {
        return STATUS_OK;
    }

    CChunkObj *c = chunk_find(chunkid);
    if (c==NULL) {
        return ERROR_NOCHUNK;
    }
    
    return c->change_file(prevgoal, newgoal);
}

int CChunkMgr::chunk_delete_file(uint64_t chunkid,uint8_t goal)
{
    CChunkObj *c = chunk_find(chunkid);

    if (c==NULL) {
        return ERROR_NOCHUNK;
    }

    return c->delete_file_int(goal);
}

int CChunkMgr::chunk_add_file(uint64_t chunkid,uint8_t goal)
{
    CChunkObj *c = chunk_find(chunkid);

    if (c==NULL) {
        return ERROR_NOCHUNK;
    }

    return c->add_file_int(goal);
}

int CChunkMgr::chunk_unlock(uint64_t chunkid)
{
    CChunkObj *c = chunk_find(chunkid);
    if (c==NULL) {
        return ERROR_NOCHUNK;
    }

    c->lockedto=0;

    return STATUS_OK;
}

#ifndef METARESTORE
int CChunkMgr::chunk_get_validcopies(uint64_t chunkid,uint8_t *vcopies) 
{
    *vcopies = 0;
    CChunkObj *c = chunk_find(chunkid);
    if (c==NULL) {
        return ERROR_NOCHUNK;
    }

    *vcopies = c->allValidCopies;
    return STATUS_OK;
}
#endif

int CChunkMgr::chunk_set_version(uint64_t chunkid,uint32_t version) 
{
    CChunkObj *c = chunk_find(chunkid);
    if (c==NULL) {
        return ERROR_NOCHUNK;
    }
    c->version = version;

    return STATUS_OK;
}

int CChunkMgr::chunk_increase_version(uint64_t chunkid)
{
    CChunkObj *c = chunk_find(chunkid);
    if (c==NULL) {
        return ERROR_NOCHUNK;
    }
    c->version++;

    return STATUS_OK;
}
