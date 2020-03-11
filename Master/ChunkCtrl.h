#ifndef _MATOCSSERV_H_
#define _MATOCSSERV_H_
#include "ChunkConn.h"
#include "ChunkJob.h"
#include "ChunkMgr.h"

#define MAX_SVR 65535
typedef void* PtrSvrList[MAX_SVR]; 

#define CSDBHASHSIZE 256
#define CSDBHASHFN(ip,port) (hash32((ip)^((port)<<16))%(CSDBHASHSIZE))

#define REPHASHSIZE 256
#define REPHASHFN(chid,ver) (((chid)^(ver)^((chid)>>8))%(REPHASHSIZE))

typedef struct ChunkSvrList {
    uint32_t ip;
    uint16_t port;

    CChunkConn *eptr;
    struct ChunkSvrList *next;
} ChunkSvrList;

typedef struct RepSrcList {
    void *src;
    struct RepSrcList *next;
} RepSrcList;

typedef struct RepDestList {
    uint64_t chunkid;
    uint32_t version;
    void *dst;
    RepSrcList *srchead;
    struct RepDestList *next;
} RepDestList;

class CChunkSvrMgr
{
protected:
    CChunkSvrMgr();
public:
    ~CChunkSvrMgr();
public:
    CChunkConn *m_chunk_list;
private:
    ChunkSvrList *m_svr_hash[CSDBHASHSIZE];
    RepDestList* m_rep_hash[REPHASHSIZE];
    RepSrcList *m_repsrc_free;
    RepDestList *m_repdst_free;
public:
    static CChunkSvrMgr* getInstance();

public:
    void init(void);
    void clear(void);
    uint32_t get_svrlist_size(void);
    void get_svrlist_data(uint8_t *ptr);
    int new_connection(uint32_t ip,uint16_t port,CChunkConn *eptr);
    void lost_connection(uint32_t ip,uint16_t port);
    int remove_server(uint32_t ip,uint16_t port);
    //
    RepSrcList* create_repsrc();
    void release_repsrc(RepSrcList *r);
    RepDestList* create_repdest();
    void release_repdest(RepDestList *r);
    //
    int replication_find(uint64_t chunkid,uint32_t version,void *dst);
    void replication_begin(uint64_t chunkid,uint32_t version,void *dst,uint8_t srccnt,void **src);
    void replication_end(uint64_t chunkid,uint32_t version,void *dst);
    void replication_disconnected(void *srv);
    //
    void get_usagedifference(double *minusage,double *maxusage,uint16_t *usablescount,uint16_t *totalscount);
    uint16_t get_servers_ordered(PtrSvrList ptrs,double maxusagediff,uint32_t *min,uint32_t *max);
    uint16_t get_servers_wrandom(PtrSvrList ptrs,double tolerance,uint16_t demand);
    uint16_t get_servers_lessrepl(PtrSvrList ptrs,uint16_t replimit);
    void get_allspace(uint64_t *totalspace,uint64_t *availspace);
};

char* matocsserv_getstrip(void *e);
int matocsserv_getlocation(void *e,uint32_t *servip,uint16_t *servport);
#define  matocsserv_replication_read_counter(e) ((CChunkConn *)e)->rrepcounter
#define matocsserv_replication_write_counter(e) ((CChunkConn *)e)->wrepcounter
#define matocsserv_deletion_counter(e) ((CChunkConn *)e)->delcounter

int matocsserv_send_replicatechunk(void *e,uint64_t chunkid,uint32_t version,void *src);
int matocsserv_send_replicatechunk_xor(void *e,uint64_t chunkid,uint32_t version,uint8_t cnt,void **src,uint64_t *srcchunkid,uint32_t *srcversion);
int matocsserv_send_chunkop(void *e,uint64_t chunkid,uint32_t version,uint32_t newversion,uint64_t copychunkid,uint32_t copyversion,uint32_t leng);
int matocsserv_send_deletechunk(void *e,uint64_t chunkid,uint32_t version);
int matocsserv_send_createchunk(void *e,uint64_t chunkid,uint32_t version);
int matocsserv_send_setchunkversion(void *e,uint64_t chunkid,uint32_t version,uint32_t oldversion);
int matocsserv_send_duplicatechunk(void *e,uint64_t chunkid,uint32_t version,uint64_t oldchunkid,uint32_t oldversion);
int matocsserv_send_truncatechunk(void *e,uint64_t chunkid,uint32_t length,uint32_t version,uint32_t oldversion);
int matocsserv_send_duptruncchunk(void *e,uint64_t chunkid,uint32_t version,uint64_t oldchunkid,uint32_t oldversion,uint32_t length);

int matocsserv_init(void);

#endif
