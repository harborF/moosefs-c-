#ifndef _CLIENT_ENTRY_MGR_H__
#define _CLIENT_ENTRY_MGR_H__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "DataPack.h"
#ifndef METARESTORE
#include "ServerCore.h"
#endif
#include "random.h"
#include "exports.h"
#include "slogger.h"
#include "ChunkJob.h"
#include "ChunkMgr.h"
#include "FileSysOpr.h"
#include "DCacheMgr.h"
#include "ChunkCtrl.h"
#include "MetaLoggerConn.h"

#define SESSION_STATS 16

enum {FUSE_WRITE,FUSE_TRUNCATE};

// locked chunks
typedef struct chunklist {
    uint64_t chunkid;
    uint64_t fleng;		// file length
    uint32_t qid;		// queryid for answer
    uint32_t inode;		// inode
    uint32_t uid;
    uint32_t gid;
    uint32_t auid;
    uint32_t agid;
    uint8_t type;
    struct chunklist *next;
} chunklist;

// opened files
typedef struct filelist {
    uint32_t inode;
    struct filelist *next;
} filelist;

typedef struct STSession {
    uint32_t sessionid;
    char *info;
    uint32_t peerip;
    uint8_t newsession;
    uint8_t sesflags;
    uint8_t mingoal;
    uint8_t maxgoal;
    uint32_t mintrashtime;
    uint32_t maxtrashtime;
    uint32_t rootuid;
    uint32_t rootgid;
    uint32_t mapalluid;
    uint32_t mapallgid;
    uint32_t rootinode;
    uint32_t disconnected;	// 0 = connected ; other = disconnection timestamp
    uint32_t nsocks;	// >0 - connected (number of active connections) ; 0 - not connected
    uint32_t curOpStats[SESSION_STATS];
    uint32_t lastHourOpStats[SESSION_STATS];
    filelist *openedfiles;
    struct STSession *next;
} STSession;

class CClientConn : public CConnEntry
{
public:
    static STSession *s_pSessHead;
    static CClientConn *s_pConnHead;
    static uint32_t s_SessSustainTime;

    static int s_exiting,s_starting;
    static uint32_t s_RejectOld;
public:
    uint8_t registered;
    uint32_t peerip;
    uint32_t version;

    uint8_t passwordrnd[32];
    STSession *sesData;
    chunklist *chunkDelayedOps;

    CClientConn *next;
public:
    void before_disconnect();
    void ugid_remap(uint32_t *auid,uint32_t *agid);
    static int insert_openfile(STSession* cr,uint32_t inode);

    void cserv_list(const uint8_t *data,uint32_t length);
    void cserv_removeserv(const uint8_t *data,uint32_t length);
    void serv_chart(const uint8_t *data,uint32_t length);
    void chart_data(const uint8_t *data,uint32_t length);
    void serv_info(const uint8_t *data,uint32_t length);
    void fstest_info(const uint8_t *data,uint32_t length);
    void chunkstest_info(const uint8_t *data,uint32_t length);
    void chunks_matrix(const uint8_t *data,uint32_t length);
    void quota_info(const uint8_t *data,uint32_t length);
    void exports_info(const uint8_t *data,uint32_t length);
    void mlog_list(const uint8_t *data,uint32_t length);
public:
    static int load_sessions();
    static void store_sessions();
    static void session_statsmove();
    static void session_check();
public:
    void session_list(const uint8_t *data,uint32_t length);
    static void init_sessions(uint32_t sessionid,uint32_t inode);
    static void close_session(uint32_t sessionid);
    static STSession* new_session(uint8_t newsession,uint8_t nonewid);
    static STSession* find_session(uint32_t sessionid);

public:
    void fuse_register(const uint8_t *data,uint32_t length);
    void fuse_reserved_inodes(const uint8_t *data,uint32_t length);
    void fuse_statfs(const uint8_t *data,uint32_t length);
    void fuse_access(const uint8_t *data,uint32_t length);
    void fuse_lookup(const uint8_t *data,uint32_t length);
    void fuse_getattr(const uint8_t *data,uint32_t length);
    void fuse_setattr(const uint8_t *data,uint32_t length);
    void fuse_truncate(const uint8_t *data,uint32_t length);
    void fuse_readlink(const uint8_t *data,uint32_t length);
    void fuse_symlink(const uint8_t *data,uint32_t length);
    void fuse_mknod(const uint8_t *data,uint32_t length);
    void fuse_mkdir(const uint8_t *data,uint32_t length);
    void fuse_unlink(const uint8_t *data,uint32_t length);
    void fuse_rmdir(const uint8_t *data,uint32_t length);
    void fuse_rename(const uint8_t *data,uint32_t length);
    void fuse_link(const uint8_t *data,uint32_t length);
    void fuse_getdir(const uint8_t *data,uint32_t length);
    void fuse_open(const uint8_t *data,uint32_t length);
    void fuse_read_chunk(const uint8_t *data,uint32_t length);
    void fuse_write_chunk(const uint8_t *data,uint32_t length);
    void fuse_write_chunk_end(const uint8_t *data,uint32_t length);
    void fuse_repair(const uint8_t *data,uint32_t length);
    void fuse_check(const uint8_t *data,uint32_t length);
    void fuse_gettrashtime(const uint8_t *data,uint32_t length);
    void fuse_settrashtime(const uint8_t *data,uint32_t length);
    void fuse_getgoal(const uint8_t *data,uint32_t length);
    void fuse_setgoal(const uint8_t *data,uint32_t length);
    void fuse_geteattr(const uint8_t *data,uint32_t length);
    void fuse_seteattr(const uint8_t *data,uint32_t length);
    void fuse_getxattr(const uint8_t *data,uint32_t length);
    void fuse_setxattr(const uint8_t *data,uint32_t length);
    void fuse_append(const uint8_t *data,uint32_t length);
    void fuse_snapshot(const uint8_t *data,uint32_t length);
    void fuse_quotacontrol(const uint8_t *data,uint32_t length);
    void fuse_getdirstats_old(const uint8_t *data,uint32_t length);
    void fuse_getdirstats(const uint8_t *data,uint32_t length);
    void fuse_gettrash(const uint8_t *data,uint32_t length);
    void fuse_getdetachedattr(const uint8_t *data,uint32_t length);
    void fuse_gettrashpath(const uint8_t *data,uint32_t length);
    void fuse_settrashpath(const uint8_t *data,uint32_t length);
    void fuse_undel(const uint8_t *data,uint32_t length);
    void fuse_purge(const uint8_t *data,uint32_t length);
    void fuse_getreserved(const uint8_t *data,uint32_t length);
};

#endif
