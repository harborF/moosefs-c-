#include "ChunkMgr.h"
#include "mfsFactory.h"
#include "FileSysOpr.h"

#ifndef METARESTORE
#include "ServerCore.h"
#endif

uint64_t CChunkMgr::s_nextchunkid=1;
CChunkObj* CChunkMgr::s_chunkhash[HASHSIZE];

static uint64_t s_lastchunkid=0;
static CChunkObj* s_lastchunkptr=NULL;

CChunkMgr::CChunkMgr()
{
    uint32_t i;
    for (i=0 ; i<HASHSIZE ; i++) {
        s_chunkhash[i]=NULL;
    }
}

CChunkMgr::~CChunkMgr()
{
}

CChunkMgr* CChunkMgr::getInstance()
{
    static CChunkMgr s_Instance;
    return &s_Instance;
}

void CChunkMgr::clear()
{    
#ifndef USE_CHUNK_BUCKETS
    uint32_t i;
    CChunkObj *ch,*chn;
    for (i=0 ; i<HASHSIZE ; i++) {
        for (ch = s_chunkhash[i] ; ch ; ch = chn) {
            ch->clear();
            chn = ch->next;
            free(ch);
        }
    }
#endif
}

#ifndef METARESTORE

void CChunkMgr::chunk_server_disconnected(void *ptr) 
{
    CChunkObj *c;
    for (uint32_t i=0 ; i<HASHSIZE; i++) {
        for (c= s_chunkhash[i] ; c ; c=c->next) 
        {
            c->disconnected(ptr);
        }
    }

    fs_cs_disconnected();
}

void CChunkMgr::chunk_damaged(void *ptr, uint64_t chunkid)
{
    CChunkObj *c = this->chunk_find(chunkid);
    if (c==NULL) {
        if (chunkid>=CChunkMgr::s_nextchunkid) {
            CChunkMgr::s_nextchunkid=chunkid+1;
        }

        c = this->chunk_new(chunkid);
        c->version = 0;
    }

    c->damaged(ptr);
}

void CChunkMgr::chunk_lost(void *ptr, uint64_t chunkid) 
{
    CChunkObj *c = this->chunk_find(chunkid);
    if (c==NULL) {
        return;
    }

    c->chunk_lost(ptr);
}

/* ---- */
void CChunkMgr::chunk_server_has_chunk(void *ptr,uint64_t chunkid,uint32_t version)
{
    CChunkObj *c = this->chunk_find(chunkid);
    if (c==NULL) {
        if (chunkid>=s_nextchunkid) {
            s_nextchunkid=chunkid+1;
        }

        c = this->chunk_new(chunkid);
        c->version = version;
        c->lockedto = (uint32_t)CServerCore::get_time()+UNUSED_DELETE_TIMEOUT;
    }

    c->has_svr_ver(ptr, version);
}


void CChunkMgr::got_delete_status(void *ptr,uint64_t chunkid,uint8_t status)
{
    CChunkObj *c = this->chunk_find(chunkid);
    if (c==NULL) {
        return ;
    }

    c->delete_status(ptr);
}

void CChunkMgr::got_replicate_status(void *ptr,uint64_t chunkid,uint32_t version,uint8_t status)
{
    if (status!=0) {
        return ;
    } 

    CChunkObj *c = this->chunk_find(chunkid);
    if (c==NULL) {
        return ;
    }

    slist *s;
    for (s=c->slisthead ; s ; s=s->next)
    {
        if (s->ptr == ptr)
        {
            syslog(LOG_WARNING,"got replication status from server which had had that CChunkObj before (CChunkObj:%016"PRIX64"_%08"PRIX32")",chunkid,version);

            if (s->valid==VALID && version!=c->version)
            {
                chunk_state_change(c->goal,c->goal,c->allValidCopies,c->allValidCopies-1,c->rValidCopies,c->rValidCopies-1);
                c->allValidCopies--;
                c->rValidCopies--;
                s->valid = INVALID;
                s->version = version;
            }

            return;
        }
    }

    s = slist_malloc();
    s->ptr = ptr;
    if (c->lockedto>=(uint32_t)CServerCore::get_time() || version!=c->version)
    {
        s->valid = INVALID;
    } else {
        chunk_state_change(c->goal,c->goal,c->allValidCopies,c->allValidCopies+1,c->rValidCopies,c->rValidCopies+1);
        c->allValidCopies++;
        c->rValidCopies++;
        s->valid = VALID;
    }

    s->version = version;
    s->next = c->slisthead;
    c->slisthead = s;
}

void CChunkMgr::got_chunkop_status(void *ptr,uint64_t chunkid,uint8_t status)
{
    CChunkObj *c = this->chunk_find(chunkid);
    if (c==NULL) {
        return ;
    }

    c->opr_status(status,ptr);
}

#endif

void CChunkMgr::chunk_dump(void) 
{
    CChunkObj *c;
    uint32_t i,lockedto,now = time(NULL);

    for (i=0 ; i<HASHSIZE ; i++)
    {
        for (c=s_chunkhash[i] ; c ; c=c->next)
        {
            lockedto = c->lockedto;
            if (lockedto<now) {
                lockedto = 0;
            }

            printf("*|i:%016"PRIX64"|v:%08"PRIX32"|g:%"PRIu8"|t:%10"PRIu32"\n",c->chunkid,c->version,c->goal,lockedto);
        }
    }
}

void CChunkMgr::chunk_newfs(void)
{
    CFileSysMgr::s_chunks = 0;
    s_nextchunkid = 1;
}

int CChunkMgr::chunk_load(FILE *fd)
{
    uint8_t hdr[8];
    uint8_t loadbuff[CHUNKFSIZE];
    const uint8_t *ptr;
    int32_t r;
    CChunkObj *c;
    // chunkdata
    uint64_t chunkid;
    uint32_t version,lockedto;

    CFileSysMgr::s_chunks = 0;

    if (fread(hdr,1,8,fd)!=8) {
        return -1;
    }

    ptr = hdr;
    s_nextchunkid = get64bit(&ptr);
    for (;;)
    {
        r = fread(loadbuff,1,CHUNKFSIZE,fd);
        if (r!=CHUNKFSIZE) {
            return -1;
        }
        ptr = loadbuff;
        chunkid = get64bit(&ptr);
        if (chunkid>0) {
            c = ChkMgr->chunk_new(chunkid);
            c->version = version = get32bit(&ptr);
            c->lockedto = lockedto = get32bit(&ptr);
        } else {
            version = get32bit(&ptr);
            lockedto = get32bit(&ptr);
            if (version==0 && lockedto==0) {
                return 0;
            } else {
                return -1;
            }
        }
    }

    return 0;
}

void CChunkMgr::chunk_store(FILE *fd)
{
    uint8_t storebuff[CHUNKFSIZE*CHUNKCNT];
    CChunkObj *c;
    // chunkdata
    uint64_t chunkid;
    uint32_t version;
    uint32_t lockedto,now;

#ifndef METARESTORE
    now = CServerCore::get_time();
#else
    now = time(NULL);
#endif

    uint8_t hdr[8];
    uint8_t *ptr = hdr;
    put64bit(&ptr, s_nextchunkid);
    if (fwrite(hdr,1,8,fd)!=(size_t)8) {
        return;
    }

    uint32_t j=0;
    ptr = storebuff;
    for (uint32_t i=0 ; i<HASHSIZE ; i++)
    {
        for (c=s_chunkhash[i] ; c ; c=c->next) {
            chunkid = c->chunkid;
            put64bit(&ptr,chunkid);
            version = c->version;
            put32bit(&ptr,version);
            lockedto = c->lockedto;
            if (lockedto<now) {
                lockedto = 0;
            }

            put32bit(&ptr,lockedto);
            j++;
            if (j==CHUNKCNT)
            {
                if (fwrite(storebuff,1,CHUNKFSIZE*CHUNKCNT,fd)!=(size_t)(CHUNKFSIZE*CHUNKCNT)) {
                    return;
                }
                j=0;
                ptr = storebuff;
            }
        }
    }

    memset(ptr,0,CHUNKFSIZE);
    j++;
    if (fwrite(storebuff,1,CHUNKFSIZE*j,fd)!=(size_t)(CHUNKFSIZE*j)) 
    {
        return;
    }
}

uint32_t CChunkMgr::chunk_count(void)
{
    return CFileSysMgr::s_chunks;
}

CChunkObj* CChunkMgr::chunk_new()
{
    return chunk_new(s_nextchunkid++);
}

CChunkObj* CChunkMgr::chunk_new(uint64_t chunkid)
{
    uint32_t chunkpos = HASHPOS(chunkid);
    CChunkObj *newchunk = chunk_malloc();

    CFileSysMgr::s_chunks++;
    CFileSysMgr::stats_all_chunks[0][0]++;
    CFileSysMgr::stats_regular_chunks[0][0]++;

    newchunk->next = s_chunkhash[chunkpos];
    s_chunkhash[chunkpos] = newchunk;
    newchunk->chunkid = chunkid;
    newchunk->version = 0;
    newchunk->goal = 0;
    newchunk->lockedto = 0;

#ifndef METARESTORE
    newchunk->allValidCopies = 0;
    newchunk->rValidCopies = 0;
    newchunk->bIncVer = 1;
    newchunk->bInterrupted = 0;
    newchunk->operation = NONE;
    newchunk->slisthead = NULL;
#endif

    newchunk->fcount = 0;
    newchunk->ftab = NULL;
    s_lastchunkid = chunkid;
    s_lastchunkptr = newchunk;

    return newchunk;
}

CChunkObj* CChunkMgr::chunk_find(uint64_t chunkid)
{
    if (s_lastchunkid==chunkid) {
        return s_lastchunkptr;
    }

    uint32_t chunkpos = HASHPOS(chunkid);
    for (CChunkObj *chunkit = s_chunkhash[chunkpos]; chunkit; chunkit = chunkit->next)
    {
        if (chunkit->chunkid == chunkid) {
            s_lastchunkid = chunkid;
            s_lastchunkptr = chunkit;
            return chunkit;
        }
    }

    return NULL;
}

void CChunkMgr::chunk_delete(CChunkObj* c)
{
    if (s_lastchunkptr==c) {
        s_lastchunkid=0;
        s_lastchunkptr=NULL;
    }

    CFileSysMgr::s_chunks--;
    CFileSysMgr::stats_all_chunks[c->goal][0]--;
    CFileSysMgr::stats_regular_chunks[c->goal][0]--;
    
    chunk_free(c);
}
