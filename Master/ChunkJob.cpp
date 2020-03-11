#include "config.h"

#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef METARESTORE
#include "cfg.h"
#include "random.h"
#include "topology.h"
#include "ServerCore.h"
#include "ChunkCtrl.h"
#include "ClientCtrl.h"
#endif

#include "ChunkJob.h"
#include "ChunkMgr.h"
#include "FileSysOpr.h"
#include "mfsFactory.h"

#define MINLOOPTIME 60
#define MAXLOOPTIME 7200
#define MAXCPS 10000000
#define MINCPS 10000

#define LOCKTIMEOUT 120

#ifndef METARESTORE
enum {JOBS_INIT,JOBS_EVERYLOOP,JOBS_EVERYSECOND};

static uint32_t ReplicationsDelayDisconnect=3600;
static uint32_t ReplicationsDelayInit=300;

static uint32_t MaxWriteRepl;
static uint32_t MaxReadRepl;
static uint32_t MaxDelSoftLimit;
static uint32_t MaxDelHardLimit;
static double TmpMaxDelFrac;
static uint32_t TmpMaxDel;
static uint32_t HashSteps;
static uint32_t HashCPS;
static double AcceptableDifference;

static uint32_t jobshpos;
static uint32_t jobsrebalancecount;
static uint32_t jobsnorepbefore;

static uint32_t starttime;

typedef struct _job_info {
    uint32_t del_invalid;
    uint32_t del_unused;
    uint32_t del_diskclean;
    uint32_t del_overgoal;
    uint32_t copy_undergoal;
} job_info;

typedef struct _loop_info {
    job_info done,notdone;
    uint32_t copy_rebalance;
} loop_info;

static loop_info chunksinfo = {{0,0,0,0,0},{0,0,0,0,0},0};
static uint32_t chunksinfo_loopstart=0,chunksinfo_loopend=0;

#endif

#ifndef METARESTORE
int chunk_multi_modify(uint64_t *nchunkid,uint64_t ochunkid,uint8_t goal,uint8_t *opflag)
{
    void* ptrs[65536];
    slist *os,*s;
    uint32_t i;
#else
int chunk_multi_modify(uint32_t ts,uint64_t *nchunkid,uint64_t ochunkid,uint8_t goal,uint8_t opflag) {
#endif
    CChunkObj *oc,*c;

    if (ochunkid==0) {	// new CChunkObj

#ifndef METARESTORE
        uint16_t servcount = CChunkSvrMgr::getInstance()->get_servers_wrandom(ptrs,AcceptableDifference/2.0,goal);
        if (servcount==0) {
            uint16_t uscount,tscount;
            double minusage,maxusage;
            CChunkSvrMgr::getInstance()->get_usagedifference(&minusage,&maxusage,&uscount,&tscount);
            if (uscount>0 && (uint32_t)(CServerCore::get_time())>(starttime+600)) {
                // if there are chunkservers and it's at least one minute after start then it means that there is no space left
                return ERROR_NOSPACE;
            } else {
                return ERROR_NOCHUNKSERVERS;
            }
        }
#endif
        c = ChkMgr->chunk_new();
        c->version = 1;
#ifndef METARESTORE
        c->bInterrupted = 0;
        c->operation = CREATE;
#endif
        c->add_file_int(goal);
#ifndef METARESTORE
       
        c->allValidCopies = c->rValidCopies = servcount<goal ? servcount : goal;

        for (i=0 ; i<c->allValidCopies ; i++) {
            s = slist_malloc();
            s->ptr = ptrs[i];
            s->valid = BUSY;
            s->version = c->version;
            s->next = c->slisthead;
            c->slisthead = s;
            matocsserv_send_createchunk(s->ptr,c->chunkid,c->version);
        }

        chunk_state_change(c->goal,c->goal,0,c->allValidCopies,0,c->rValidCopies);
        *opflag=1;
#endif
        *nchunkid = c->chunkid;
    } else {
        c = NULL;
        oc = ChkMgr->chunk_find(ochunkid);
        if (oc==NULL) {
            return ERROR_NOCHUNK;
        }
#ifndef METARESTORE
        if (oc->lockedto>=(uint32_t)CServerCore::get_time()) {
            return ERROR_LOCKED;
        }
#endif
        if (oc->fcount==1) {	// refcount==1
            *nchunkid = ochunkid;
            c = oc;
#ifndef METARESTORE

            if (c->operation!=NONE) {
                return ERROR_CHUNKBUSY;
            }

            if (c->bIncVer) {
                i=0;
                for (s=c->slisthead ;s ; s=s->next) {
                    if (s->valid!=INVALID && s->valid!=DEL) {
                        if (s->valid==TDVALID || s->valid==TDBUSY) {
                            s->valid = TDBUSY;
                        } else {
                            s->valid = BUSY;
                        }
                        s->version = c->version+1;
                        matocsserv_send_setchunkversion(s->ptr,ochunkid,c->version+1,c->version);
                        i++;
                    }
                }

                if (i>0) {
                    c->bInterrupted = 0;
                    c->operation = SET_VERSION;
                    c->version++;
                    *opflag=1;
                } else {
                    return ERROR_CHUNKLOST;
                }
            } else {
                *opflag=0;
            }
#else
            if (opflag) {
                c->version++;
            }
#endif
        } else {
            if (oc->fcount==0/* f==NULL */) {	// it's serious structure error
#ifndef METARESTORE
                syslog(LOG_WARNING,"serious structure inconsistency: (chunkid:%016"PRIX64")",ochunkid);
#else
                printf("serious structure inconsistency: (chunkid:%016"PRIX64")\n",ochunkid);
#endif
                return ERROR_CHUNKLOST;	// ERROR_STRUCTURE
            }
#ifndef METARESTORE
            i=0;
            for (os=oc->slisthead ;os ; os=os->next) {
                if (os->valid!=INVALID && os->valid!=DEL) {
                    if (c==NULL) {
#endif
                        c = ChkMgr->chunk_new();
                        c->version = 1;
#ifndef METARESTORE
                        c->bInterrupted = 0;
                        c->operation = DUPLICATE;
#endif
                        oc->delete_file_int(goal);
                        c->add_file_int(goal);
#ifndef METARESTORE
                    }
                    s = slist_malloc();
                    s->ptr = os->ptr;
                    s->valid = BUSY;
                    s->version = c->version;
                    s->next = c->slisthead;
                    c->slisthead = s;
                    c->allValidCopies++;
                    c->rValidCopies++;
                    matocsserv_send_duplicatechunk(s->ptr,c->chunkid,c->version,oc->chunkid,oc->version);
                    i++;
                }
            }
            if (c!=NULL) {
                chunk_state_change(c->goal,c->goal,0,c->allValidCopies,0,c->rValidCopies);
            }
            if (i>0) {
#endif
                *nchunkid = c->chunkid;
#ifndef METARESTORE
                *opflag=1;
            } else {
                return ERROR_CHUNKLOST;
            }
#endif
        }
    }

#ifndef METARESTORE
    c->lockedto=(uint32_t)CServerCore::get_time()+LOCKTIMEOUT;
#else
    c->lockedto=ts+LOCKTIMEOUT;
#endif
    return STATUS_OK;
}

#ifndef METARESTORE
int chunk_multi_truncate(uint64_t *nchunkid,uint64_t ochunkid,uint32_t length,uint8_t goal) {
    slist *os,*s;
    uint32_t i;
#else
int chunk_multi_truncate(uint32_t ts,uint64_t *nchunkid,uint64_t ochunkid,uint8_t goal) {
#endif
    CChunkObj *oc,*c=NULL;
    oc = ChkMgr->chunk_find(ochunkid);
    if (oc==NULL) {
        return ERROR_NOCHUNK;
    }
#ifndef METARESTORE
    if (oc->lockedto>=(uint32_t)CServerCore::get_time()) {
        return ERROR_LOCKED;
    }
#endif

    if (oc->fcount==1) {	// refcount==1
        *nchunkid = ochunkid;
        c = oc;
#ifndef METARESTORE
        if (c->operation!=NONE) {
            return ERROR_CHUNKBUSY;
        }
        i=0;
        for (s=c->slisthead ;s ; s=s->next) {
            if (s->valid!=INVALID && s->valid!=DEL) {
                if (s->valid==TDVALID || s->valid==TDBUSY) {
                    s->valid = TDBUSY;
                } else {
                    s->valid = BUSY;
                }
                s->version = c->version+1;
                matocsserv_send_truncatechunk(s->ptr,ochunkid,length,c->version+1,c->version);
                i++;
            }
        }
        if (i>0) {
            c->bInterrupted = 0;
            c->operation = TRUNCATE;
            c->version++;
        } else {
            return ERROR_CHUNKLOST;
        }
#else
        c->version++;
#endif
    } else {
        if (oc->fcount==0/*f==NULL*/) {	// it's serious structure error
#ifndef METARESTORE
            syslog(LOG_WARNING,"serious structure inconsistency: (chunkid:%016"PRIX64")",ochunkid);
#else
            printf("serious structure inconsistency: (chunkid:%016"PRIX64")\n",ochunkid);
#endif
            return ERROR_CHUNKLOST;	// ERROR_STRUCTURE
        }

#ifndef METARESTORE
        i=0;
        for (os=oc->slisthead ;os ; os=os->next) {
            if (os->valid!=INVALID && os->valid!=DEL) {
                if (c==NULL) {
#endif
                    c = ChkMgr->chunk_new();
                    c->version = 1;
#ifndef METARESTORE
                    c->bInterrupted = 0;
                    c->operation = DUPTRUNC;
#endif
                    oc->delete_file_int(goal);
                    c->add_file_int(goal);
#ifndef METARESTORE
                }
                s = slist_malloc();
                s->ptr = os->ptr;
                s->valid = BUSY;
                s->version = c->version;
                s->next = c->slisthead;
                c->slisthead = s;
                c->allValidCopies++;
                c->rValidCopies++;
                matocsserv_send_duptruncchunk(s->ptr,c->chunkid,c->version,oc->chunkid,oc->version,length);
                i++;
            }
        }

        if (c!=NULL) {
            chunk_state_change(c->goal,c->goal,0,c->allValidCopies,0,c->rValidCopies);
        }

        if (i>0) {
#endif
            *nchunkid = c->chunkid;
#ifndef METARESTORE
        } else {
            return ERROR_CHUNKLOST;
        }
#endif
    }

#ifndef METARESTORE
    c->lockedto=(uint32_t)CServerCore::get_time()+LOCKTIMEOUT;
#else
    c->lockedto=ts+LOCKTIMEOUT;
#endif

    return STATUS_OK;
}

#ifndef METARESTORE
int chunk_repair(uint8_t goal,uint64_t ochunkid,uint32_t *nversion)
{
    *nversion=0;
    if (ochunkid==0) {
        return 0;	// not changed
    }

    CChunkObj *c = ChkMgr->chunk_find(ochunkid);
    if (c==NULL) {	// no such CChunkObj - erase (nchunkid already is 0 - so just return with "changed" status)
        return 1;
    }
    if (c->lockedto>=(uint32_t)CServerCore::get_time()) { // can't repair locked chunks - but if it's locked, then likely it doesn't need to be repaired
        return 0;
    }

    slist *s;
    uint32_t bestversion = 0;
    for (s=c->slisthead ; s ; s=s->next) {
        if (s->valid == VALID || s->valid == TDVALID || s->valid == BUSY || s->valid == TDBUSY) {	// found CChunkObj that is ok - so return
            return 0;
        }
        if (s->valid == INVALID) {
            if (s->version>=bestversion) {
                bestversion = s->version;
            }
        }
    }

    if (bestversion==0) {	// didn't find sensible CChunkObj - so erase it
        c->delete_file_int(goal);
        return 1;
    }

    if (c->allValidCopies>0 || c->rValidCopies>0) {
        if (c->allValidCopies>0) {
            syslog(LOG_WARNING,"wrong all valid copies counter - (counter value: %u, should be: 0) - fixed",c->allValidCopies);
        }
        if (c->rValidCopies>0) {
            syslog(LOG_WARNING,"wrong regular valid copies counter - (counter value: %u, should be: 0) - fixed",c->rValidCopies);
        }
        chunk_state_change(c->goal,c->goal,c->allValidCopies,0,c->rValidCopies,0);
        c->allValidCopies = 0;
        c->rValidCopies = 0;
    }

    c->version = bestversion;
    for (s=c->slisthead ; s ; s=s->next) {
        if (s->valid == INVALID && s->version==bestversion) {
            s->valid = VALID;
            c->allValidCopies++;
            c->rValidCopies++;
        }
    }
    *nversion = bestversion;
    chunk_state_change(c->goal,c->goal,0,c->allValidCopies,0,c->rValidCopies);
    c->bIncVer=1;

    return 1;
}
#endif

/* ---- */

#ifndef METARESTORE

typedef struct locsort {
    uint32_t ip;
    uint16_t port;
    uint32_t dist;
    uint32_t rnd;
} locsort;

int chunk_locsort_cmp(const void *aa,const void *bb) {
    const locsort *a = (const locsort*)aa;
    const locsort *b = (const locsort*)bb;
    if (a->dist<b->dist) {
        return -1;
    } else if (a->dist>b->dist) {
        return 1;
    } else if (a->rnd<b->rnd) {
        return -1;
    } else if (a->rnd>b->rnd) {
        return 1;
    }
    return 0;
}

int get_version_locations(uint64_t chunkid,uint32_t cuip,uint32_t *version,uint8_t *count,uint8_t loc[100*6])
{
    CChunkObj *c = ChkMgr->chunk_find(chunkid);
    if (c==NULL) {
        return ERROR_NOCHUNK;
    }

    *version = c->version;

    uint8_t cnt=0;
    locsort lstab[100];
    for (slist *s=c->slisthead ;s ; s=s->next)
    {
        if (s->valid!=INVALID && s->valid!=DEL)
        {
            if (cnt<100 && matocsserv_getlocation(s->ptr,&(lstab[cnt].ip),&(lstab[cnt].port))==0)
            {
                lstab[cnt].dist = topology_distance(lstab[cnt].ip,cuip);
                lstab[cnt].rnd = rndu32();
                cnt++;
            }
        }
    }

    qsort(lstab,cnt,sizeof(locsort),chunk_locsort_cmp);
    uint8_t *wptr = loc;
    for (uint8_t i=0 ; i<cnt ; i++) {
        put32bit(&wptr,lstab[i].ip);
        put16bit(&wptr,lstab[i].port);
    }

    *count = cnt;
    return STATUS_OK;
}

/* ----------------------- */
/* JOBS (DELETE/REPLICATE) */
/* ----------------------- */
void chunk_store_info(uint8_t *buff)
{
    put32bit(&buff,chunksinfo_loopstart);
    put32bit(&buff,chunksinfo_loopend);
    put32bit(&buff,chunksinfo.done.del_invalid);
    put32bit(&buff,chunksinfo.notdone.del_invalid);
    put32bit(&buff,chunksinfo.done.del_unused);
    put32bit(&buff,chunksinfo.notdone.del_unused);
    put32bit(&buff,chunksinfo.done.del_diskclean);
    put32bit(&buff,chunksinfo.notdone.del_diskclean);
    put32bit(&buff,chunksinfo.done.del_overgoal);
    put32bit(&buff,chunksinfo.notdone.del_overgoal);
    put32bit(&buff,chunksinfo.done.copy_undergoal);
    put32bit(&buff,chunksinfo.notdone.copy_undergoal);
    put32bit(&buff,chunksinfo.copy_rebalance);
}

//jobs state: jobshpos
void chunk_do_jobs(CChunkObj *c,uint16_t scount,double minusage,double maxusage) 
{
    slist *s;
    static void* ptrs[65535];
    static uint16_t servcount;
    static uint32_t min,max;
    void* rptrs[65536];
    uint16_t rservcount;
    void *srcptr;
    uint16_t i;
    uint32_t vc,tdc,ivc,bc,tdb,dc;
    static loop_info inforec;
    static uint32_t delnotdone;
    static uint32_t deldone;
    static uint32_t prevtodeletecount;
    static uint32_t delloopcnt;

    if (c==NULL) {
        if (scount==JOBS_INIT) { // init tasks
            delnotdone = 0;
            deldone = 0;
            prevtodeletecount = 0;
            delloopcnt = 0;
            memset(&inforec,0,sizeof(loop_info));
        }
        else if (scount==JOBS_EVERYLOOP)
        { // every loop tasks
            delloopcnt++;
            if (delloopcnt>=16) 
            {
                uint32_t todeletecount = deldone+delnotdone;
                delloopcnt=0;

                if ((delnotdone > deldone) && (todeletecount > prevtodeletecount)) {
                    TmpMaxDelFrac *= 1.5;
                    if (TmpMaxDelFrac>MaxDelHardLimit) {
                        syslog(LOG_NOTICE,"DEL_LIMIT hard limit (%"PRIu32" per server) reached",MaxDelHardLimit);
                        TmpMaxDelFrac=MaxDelHardLimit;
                    }
                    TmpMaxDel = TmpMaxDelFrac;
                    syslog(LOG_NOTICE,"DEL_LIMIT temporary increased to: %"PRIu32" per server",TmpMaxDel);
                }

                if ((todeletecount < prevtodeletecount) && (TmpMaxDelFrac > MaxDelSoftLimit)) {
                    TmpMaxDelFrac /= 1.5;
                    if (TmpMaxDelFrac<MaxDelSoftLimit) {
                        syslog(LOG_NOTICE,"DEL_LIMIT back to soft limit (%"PRIu32" per server)",MaxDelSoftLimit);
                        TmpMaxDelFrac = MaxDelSoftLimit;
                    }
                    TmpMaxDel = TmpMaxDelFrac;
                    syslog(LOG_NOTICE,"DEL_LIMIT decreased back to: %"PRIu32" per server",TmpMaxDel);
                }

                prevtodeletecount = todeletecount;
                delnotdone = 0;
                deldone = 0;
            }

            chunksinfo = inforec;
            memset(&inforec,0,sizeof(inforec));
            chunksinfo_loopstart = chunksinfo_loopend;
            chunksinfo_loopend = CServerCore::get_time();
        } else if (scount==JOBS_EVERYSECOND) { // every second tasks
            servcount=0;
        }

        return;
    }

    // step 1. calculate number of valid and invalid copies
    vc=tdc=ivc=bc=tdb=dc=0;
    for (s=c->slisthead ; s ; s=s->next) {
        switch (s->valid) {
        case INVALID:  ivc++;       break;
        case TDVALID:  tdc++;       break;
        case VALID:    vc++;        break;
        case TDBUSY:   tdb++;       break;
        case BUSY:     bc++;        break;
        case DEL:      dc++;        break;
        }
    }

    if (c->allValidCopies!=vc+tdc+bc+tdb) {
        syslog(LOG_WARNING,"wrong all valid copies counter - (counter value: %u, should be: %u) - fixed",c->allValidCopies,vc+tdc+bc+tdb);
        chunk_state_change(c->goal,c->goal,c->allValidCopies,vc+tdc+bc+tdb,c->rValidCopies,c->rValidCopies);
        c->allValidCopies = vc+tdc+bc+tdb;
    }

    if (c->rValidCopies!=vc+bc) {
        syslog(LOG_WARNING,"wrong regular valid copies counter - (counter value: %u, should be: %u) - fixed",c->rValidCopies,vc+bc);
        chunk_state_change(c->goal,c->goal,c->allValidCopies,c->allValidCopies,c->rValidCopies,vc+bc);
        c->rValidCopies = vc+bc;
    }

    // step 2. check number of copies
    if (tdc+vc+tdb+bc==0 && ivc>0 && c->fcount>0/* c->flisthead */) {
        syslog(LOG_WARNING,"CChunkObj %016"PRIX64" has only invalid copies (%"PRIu32") - please repair it manually",c->chunkid,ivc);
        for (s=c->slisthead ; s ; s=s->next) {
            syslog(LOG_NOTICE,"CChunkObj %016"PRIX64"_%08"PRIX32" - invalid copy on (%s - ver:%08"PRIX32")",c->chunkid,c->version,matocsserv_getstrip(s->ptr),s->version);
        }
        return ;
    }

    // step 3. delete invalid copies
    for (s=c->slisthead ; s ; s=s->next) {
        if (matocsserv_deletion_counter(s->ptr)<TmpMaxDel) {
            if (s->valid==INVALID || s->valid==DEL) {
                if (s->valid==DEL) {
                    syslog(LOG_WARNING,"CChunkObj hasn't been deleted since previous loop - retry");
                }
                s->valid = DEL;
                CFileSysMgr::stats_deletions++;
                matocsserv_send_deletechunk(s->ptr,c->chunkid,0);
                inforec.done.del_invalid++;
                deldone++;
                dc++;
                ivc--;
            }
        } else {
            if (s->valid==INVALID) {
                inforec.notdone.del_invalid++;
                delnotdone++;
            }
        }
    }

    // step 4. return if CChunkObj is during some operation
    if (c->operation!=NONE || (c->lockedto>=(uint32_t)CServerCore::get_time())) {
        return ;
    }

    // step 5. check busy count
    if ((bc+tdb)>0) {
        syslog(LOG_WARNING,"CChunkObj %016"PRIX64" has unexpected BUSY copies",c->chunkid);
        return ;
    }

    // step 6. delete unused CChunkObj
    if (c->fcount==0/* c->flisthead==NULL */) {
        //		syslog(LOG_WARNING,"unused - delete");
        for (s=c->slisthead ; s ; s=s->next)
        {
            if (matocsserv_deletion_counter(s->ptr)<TmpMaxDel)
            {
                if (s->valid==VALID || s->valid==TDVALID) {
                    if (s->valid==TDVALID) {
                        chunk_state_change(c->goal,c->goal,c->allValidCopies,c->allValidCopies-1,c->rValidCopies,c->rValidCopies);
                        c->allValidCopies--;
                    } else {
                        chunk_state_change(c->goal,c->goal,c->allValidCopies,c->allValidCopies-1,c->rValidCopies,c->rValidCopies-1);
                        c->allValidCopies--;
                        c->rValidCopies--;
                    }
                    c->bIncVer=1;
                    s->valid = DEL;
                    CFileSysMgr::stats_deletions++;
                    matocsserv_send_deletechunk(s->ptr,c->chunkid,c->version);
                    inforec.done.del_unused++;
                    deldone++;
                }
            } else {
                if (s->valid==VALID || s->valid==TDVALID) {
                    inforec.notdone.del_unused++;
                    delnotdone++;
                }
            }
        }//end for

        return ;
    }

    // step 7b. if CChunkObj has too many copies then delete some of them
    if (vc > c->goal)
    {
        if (servcount==0) {
            servcount = CChunkSvrMgr::getInstance()->get_servers_ordered(ptrs,AcceptableDifference/2.0,&min,&max);
        }

        inforec.notdone.del_overgoal+=(vc-(c->goal));
        delnotdone+=(vc-(c->goal));
        uint8_t prevdone = 1;
        for (i=0 ; i<servcount && vc>c->goal && prevdone; i++)
        {
            for (s=c->slisthead ; s && s->ptr!=ptrs[servcount-1-i] ; s=s->next) {}

            if (s && s->valid==VALID) {
                if (matocsserv_deletion_counter(s->ptr)<TmpMaxDel) {
                    chunk_state_change(c->goal,c->goal,c->allValidCopies,c->allValidCopies-1,c->rValidCopies,c->rValidCopies-1);
                    c->allValidCopies--;
                    c->rValidCopies--;
                    c->bIncVer=1;
                    s->valid = DEL;
                    CFileSysMgr::stats_deletions++;
                    matocsserv_send_deletechunk(s->ptr,c->chunkid,0);
                    inforec.done.del_overgoal++;
                    inforec.notdone.del_overgoal--;
                    deldone++;
                    delnotdone--;
                    vc--;
                    dc++;
                } else {
                    prevdone=0;
                }
            }
        }//end for

        return;
    }

    // step 7c. if CChunkObj has one copy on each server and some of them have status TODEL then delete one of it
    if (vc+tdc>=scount && vc<c->goal && tdc>0 && vc+tdc>1)
    {
        uint8_t prevdone = 0;
        //syslog(LOG_WARNING,"vc+tdc (%"PRIu32") >= scount (%"PRIu32") and vc (%"PRIu32") < goal (%"PRIu32") and tdc (%"PRIu32") > 0 and vc+tdc > 1 - delete",vc+tdc,scount,vc,c->goal,tdc);
        for (s=c->slisthead ; s && prevdone==0 ; s=s->next)
        {
            if (s->valid==TDVALID) {
                if (matocsserv_deletion_counter(s->ptr)<TmpMaxDel) 
                {
                    chunk_state_change(c->goal,c->goal,c->allValidCopies,c->allValidCopies-1,c->rValidCopies,c->rValidCopies);
                    c->allValidCopies--;
                    c->bIncVer=1;
                    s->valid = DEL;
                    CFileSysMgr::stats_deletions++;
                    matocsserv_send_deletechunk(s->ptr,c->chunkid,0);
                    inforec.done.del_diskclean++;
                    tdc--;
                    dc++;
                    prevdone = 1;
                } else {
                    inforec.notdone.del_diskclean++;
                }
            }
        }//end for

        return;
    }

    //step 8. if CChunkObj has number of copies less than goal then make another copy of this CChunkObj
    if (c->goal > vc && vc+tdc > 0) {
        if (jobsnorepbefore<(uint32_t)CServerCore::get_time())
        {
            rservcount = CChunkSvrMgr::getInstance()->get_servers_lessrepl(rptrs,MaxWriteRepl);
            uint32_t rgvc=0,rgtdc=0;
            for (s=c->slisthead ; s ; s=s->next) {
                if (matocsserv_replication_read_counter(s->ptr)<MaxReadRepl) {
                    if (s->valid==VALID) {
                        rgvc++;
                    } else if (s->valid==TDVALID) {
                        rgtdc++;
                    }
                }
            }

            if (rgvc+rgtdc>0 && rservcount>0) { // have at least one server to read from and at least one to write to
                for (i=0 ; i<rservcount ; i++) 
                {
                    for (s=c->slisthead ; s && s->ptr!=rptrs[i] ; s=s->next) {}

                    if (!s) {
                        uint32_t r;
                        if (rgvc>0) {	// if there are VALID copies then make copy of one VALID CChunkObj
                            r = 1+rndu32_ranged(rgvc);
                            srcptr = NULL;
                            for (s=c->slisthead ; s && r>0 ; s=s->next) {
                                if (matocsserv_replication_read_counter(s->ptr)<MaxReadRepl && s->valid==VALID) {
                                    r--;
                                    srcptr = s->ptr;
                                }
                            }
                        } else {	// if not then use TDVALID chunks.
                            r = 1+rndu32_ranged(rgtdc);
                            srcptr = NULL;
                            for (s=c->slisthead ; s && r>0 ; s=s->next) {
                                if (matocsserv_replication_read_counter(s->ptr)<MaxReadRepl && s->valid==TDVALID) {
                                    r--;
                                    srcptr = s->ptr;
                                }
                            }
                        }

                        if (srcptr) {
                            CFileSysMgr::stats_replications++;
                            // matocsserv_getlocation(srcptr,&ip,&port);
                            matocsserv_send_replicatechunk(rptrs[i],c->chunkid,c->version,srcptr);
                            c->bIncVer=1;
                            inforec.done.copy_undergoal++;
                            return;
                        }
                    }
                }//end for
            }//end if
        }//end if

        inforec.notdone.copy_undergoal++;
    }

    if (chunksinfo.notdone.copy_undergoal>0 && chunksinfo.done.copy_undergoal>0) {
        return;
    }

    // step 9. if there is too big difference between chunkservers then make copy of CChunkObj from server with biggest disk usage on server with lowest disk usage
    if (c->goal >= vc && vc+tdc>0 && (maxusage-minusage)>AcceptableDifference) {
        if (servcount==0) {
            servcount = CChunkSvrMgr::getInstance()->get_servers_ordered(ptrs,AcceptableDifference/2.0,&min,&max);
        }

        if (min>0 || max>0) {
            void *srcserv=NULL;
            void *dstserv=NULL;
            if (max>0) {
                for (i=0 ; i<max && srcserv==NULL ; i++) {
                    if (matocsserv_replication_read_counter(ptrs[servcount-1-i])<MaxReadRepl) {
                        for (s=c->slisthead ; s && s->ptr!=ptrs[servcount-1-i] ; s=s->next ) {}
                        if (s && (s->valid==VALID || s->valid==TDVALID)) {
                            srcserv=s->ptr;
                        }
                    }
                }
            } else {
                for (i=0 ; i<(servcount-min) && srcserv==NULL ; i++) {
                    if (matocsserv_replication_read_counter(ptrs[servcount-1-i])<MaxReadRepl) {
                        for (s=c->slisthead ; s && s->ptr!=ptrs[servcount-1-i] ; s=s->next ) {}
                        if (s && (s->valid==VALID || s->valid==TDVALID)) {
                            srcserv=s->ptr;
                        }
                    }
                }
            }

            if (srcserv!=NULL) {
                if (min>0) {
                    for (i=0 ; i<min && dstserv==NULL ; i++) {
                        if (matocsserv_replication_write_counter(ptrs[i])<MaxWriteRepl) {
                            for (s=c->slisthead ; s && s->ptr!=ptrs[i] ; s=s->next ) {}
                            if (s==NULL) {
                                dstserv=ptrs[i];
                            }
                        }
                    }
                } else {
                    for (i=0 ; i<servcount-max && dstserv==NULL ; i++) {
                        if (matocsserv_replication_write_counter(ptrs[i])<MaxWriteRepl) {
                            for (s=c->slisthead ; s && s->ptr!=ptrs[i] ; s=s->next ) {}
                            if (s==NULL) {
                                dstserv=ptrs[i];
                            }
                        }
                    }
                }

                if (dstserv!=NULL) {
                    CFileSysMgr::stats_replications++;
                    matocsserv_send_replicatechunk(dstserv,c->chunkid,c->version,srcserv);
                    c->bIncVer=1;
                    inforec.copy_rebalance++;
                }
            }
        }
    }
}

void chunk_jobs_main(void) 
{
    uint32_t i,l,lc,r;
    CChunkObj *c,**cp;

    if (starttime+ReplicationsDelayInit>CServerCore::get_time()) {
        return;
    }

    uint16_t uscount,tscount;
    double minusage,maxusage;
    CChunkSvrMgr::getInstance()->get_usagedifference(&minusage,&maxusage,&uscount,&tscount);

    static uint16_t lasttscount=0, maxtscount=0;
    if (tscount<lasttscount) {		// servers disconnected
        jobsnorepbefore = CServerCore::get_time()+ReplicationsDelayDisconnect;
    } else if (tscount>lasttscount) {	// servers connected
        if (tscount>=maxtscount) {
            maxtscount = tscount;
            jobsnorepbefore = CServerCore::get_time();
        }
    } else if (tscount<maxtscount && (uint32_t)CServerCore::get_time()>jobsnorepbefore) {
        maxtscount = tscount;
    }
    lasttscount = tscount;

    if (minusage>maxusage) {
        return;
    }

    chunk_do_jobs(NULL,JOBS_EVERYSECOND,0.0,0.0);	// every second tasks
    lc = 0;
    for (i=0 ; i<HashSteps && lc<HashCPS ; i++) {
        if (jobshpos==0) {
            chunk_do_jobs(NULL,JOBS_EVERYLOOP,0.0,0.0);	// every loop tasks
        }
        // delete unused chunks from structures
        l=0;
        cp = &(CChunkMgr::s_chunkhash[jobshpos]);
        while ((c=*cp)!=NULL) {
            if (c->fcount==0 && c->slisthead==NULL) {
                *cp = (c->next);
                ChkMgr->chunk_delete(c);
            } else {
                cp = &(c->next);
                l++;
                lc++;
            }
        }
        if (l>0) {
            r = rndu32_ranged(l);
            l=0;
            // do jobs on rest of them
            for (c=CChunkMgr::s_chunkhash[jobshpos] ; c ; c=c->next) {
                if (l>=r) {
                    chunk_do_jobs(c,uscount,minusage,maxusage);
                }
                l++;
            }
            l=0;
            for (c=CChunkMgr::s_chunkhash[jobshpos] ; l<r && c ; c=c->next) {
                chunk_do_jobs(c,uscount,minusage,maxusage);
                l++;
            }
        }
        jobshpos+=123;	// if HASHSIZE is any power of 2 then any odd number is good here
        jobshpos%=HASHSIZE;
    }
}

#endif

void chunk_term(void) {
    ChkMgr->clear();
}

#ifndef METARESTORE
void chunk_reload(void) {

    ReplicationsDelayInit = cfg_getuint32("REPLICATIONS_DELAY_INIT",300);
    ReplicationsDelayDisconnect = cfg_getuint32("REPLICATIONS_DELAY_DISCONNECT",3600);

    uint32_t oldMaxDelSoftLimit,oldMaxDelHardLimit;
    oldMaxDelSoftLimit = MaxDelSoftLimit;
    oldMaxDelHardLimit = MaxDelHardLimit;

    MaxDelSoftLimit = cfg_getuint32("CHUNKS_SOFT_DEL_LIMIT",10);
    if (cfg_isdefined("CHUNKS_HARD_DEL_LIMIT")) {
        MaxDelHardLimit = cfg_getuint32("CHUNKS_HARD_DEL_LIMIT",25);
        if (MaxDelHardLimit<MaxDelSoftLimit) {
            MaxDelSoftLimit = MaxDelHardLimit;
            syslog(LOG_WARNING,"CHUNKS_SOFT_DEL_LIMIT is greater than CHUNKS_HARD_DEL_LIMIT - using CHUNKS_HARD_DEL_LIMIT for both");
        }
    } else {
        MaxDelHardLimit = 3 * MaxDelSoftLimit;
    }

    if (MaxDelSoftLimit==0) {
        MaxDelSoftLimit = oldMaxDelSoftLimit;
        MaxDelHardLimit = oldMaxDelHardLimit;
    }
    if (TmpMaxDelFrac<MaxDelSoftLimit) {
        TmpMaxDelFrac = MaxDelSoftLimit;
    }
    if (TmpMaxDelFrac>MaxDelHardLimit) {
        TmpMaxDelFrac = MaxDelHardLimit;
    }
    if (TmpMaxDel<MaxDelSoftLimit) {
        TmpMaxDel = MaxDelSoftLimit;
    }
    if (TmpMaxDel>MaxDelHardLimit) {
        TmpMaxDel = MaxDelHardLimit;
    }
    
    uint32_t repl = cfg_getuint32("CHUNKS_WRITE_REP_LIMIT",2);
    if (repl>0) {
        MaxWriteRepl = repl;
    }

    repl = cfg_getuint32("CHUNKS_READ_REP_LIMIT",10);
    if (repl>0) {
        MaxReadRepl = repl;
    }

    uint32_t looptime;
    if (cfg_isdefined("CHUNKS_LOOP_TIME")) {
        looptime = cfg_getuint32("CHUNKS_LOOP_TIME",300);
        if (looptime < MINLOOPTIME) {
            syslog(LOG_NOTICE,"CHUNKS_LOOP_TIME value too low (%"PRIu32") increased to %u",looptime,MINLOOPTIME);
            looptime = MINLOOPTIME;
        }
        if (looptime > MAXLOOPTIME) {
            syslog(LOG_NOTICE,"CHUNKS_LOOP_TIME value too high (%"PRIu32") decreased to %u",looptime,MAXLOOPTIME);
            looptime = MAXLOOPTIME;
        }
        HashSteps = 1+((HASHSIZE)/looptime);
        HashCPS = 0xFFFFFFFF;
    } else {
        looptime = cfg_getuint32("CHUNKS_LOOP_MIN_TIME",300);
        if (looptime < MINLOOPTIME) {
            syslog(LOG_NOTICE,"CHUNKS_LOOP_MIN_TIME value too low (%"PRIu32") increased to %u",looptime,MINLOOPTIME);
            looptime = MINLOOPTIME;
        }
        if (looptime > MAXLOOPTIME) {
            syslog(LOG_NOTICE,"CHUNKS_LOOP_MIN_TIME value too high (%"PRIu32") decreased to %u",looptime,MAXLOOPTIME);
            looptime = MAXLOOPTIME;
        }
        HashSteps = 1+((HASHSIZE)/looptime);
        HashCPS = cfg_getuint32("CHUNKS_LOOP_MAX_CPS",100000);
        if (HashCPS < MINCPS) {
            syslog(LOG_NOTICE,"CHUNKS_LOOP_MAX_CPS value too low (%"PRIu32") increased to %u",HashCPS,MINCPS);
            HashCPS = MINCPS;
        }
        if (HashCPS > MAXCPS) {
            syslog(LOG_NOTICE,"CHUNKS_LOOP_MAX_CPS value too high (%"PRIu32") decreased to %u",HashCPS,MAXCPS);
            HashCPS = MAXCPS;
        }
    }

    AcceptableDifference = cfg_getdouble("ACCEPTABLE_DIFFERENCE",0.05);
    if (AcceptableDifference<0.01) {
        AcceptableDifference = 0.01;
    }
    if (AcceptableDifference>0.1) {
        AcceptableDifference = 0.1;
    }
}
#endif

int chunk_strinit(void)
{
#ifndef METARESTORE
    ReplicationsDelayInit = cfg_getuint32("REPLICATIONS_DELAY_INIT",300);
    ReplicationsDelayDisconnect = cfg_getuint32("REPLICATIONS_DELAY_DISCONNECT",3600);
    MaxDelSoftLimit = cfg_getuint32("CHUNKS_SOFT_DEL_LIMIT",10);
    if (cfg_isdefined("CHUNKS_HARD_DEL_LIMIT")) {
        MaxDelHardLimit = cfg_getuint32("CHUNKS_HARD_DEL_LIMIT",25);
        if (MaxDelHardLimit<MaxDelSoftLimit) {
            MaxDelSoftLimit = MaxDelHardLimit;
            fprintf(stderr,"CHUNKS_SOFT_DEL_LIMIT is greater than CHUNKS_HARD_DEL_LIMIT - using CHUNKS_HARD_DEL_LIMIT for both\n");
        }
    } else {
        MaxDelHardLimit = 3 * MaxDelSoftLimit;
    }

    if (MaxDelSoftLimit==0) {
        fprintf(stderr,"delete limit is zero !!!\n");
        return -1;
    }

    TmpMaxDelFrac = MaxDelSoftLimit;
    TmpMaxDel = MaxDelSoftLimit;
    MaxWriteRepl = cfg_getuint32("CHUNKS_WRITE_REP_LIMIT",2);
    MaxReadRepl = cfg_getuint32("CHUNKS_READ_REP_LIMIT",10);
    if (MaxReadRepl==0) {
        fprintf(stderr,"read replication limit is zero !!!\n");
        return -1;
    }

    if (MaxWriteRepl==0) {
        fprintf(stderr,"write replication limit is zero !!!\n");
        return -1;
    }

    uint32_t looptime;
    if (cfg_isdefined("CHUNKS_LOOP_TIME")) {
        fprintf(stderr,"Defining loop time by CHUNKS_LOOP_TIME option is deprecated - use CHUNKS_LOOP_MAX_CPS and CHUNKS_LOOP_MIN_TIME\n");
        looptime = cfg_getuint32("CHUNKS_LOOP_TIME",300);
        if (looptime < MINLOOPTIME) {
            fprintf(stderr,"CHUNKS_LOOP_TIME value too low (%"PRIu32") increased to %u\n",looptime,MINLOOPTIME);
            looptime = MINLOOPTIME;
        }
        if (looptime > MAXLOOPTIME) {
            fprintf(stderr,"CHUNKS_LOOP_TIME value too high (%"PRIu32") decreased to %u\n",looptime,MAXLOOPTIME);
            looptime = MAXLOOPTIME;
        }
        HashSteps = 1+((HASHSIZE)/looptime);
        HashCPS = 0xFFFFFFFF;
    } else {
        looptime = cfg_getuint32("CHUNKS_LOOP_MIN_TIME",300);
        if (looptime < MINLOOPTIME) {
            fprintf(stderr,"CHUNKS_LOOP_MIN_TIME value too low (%"PRIu32") increased to %u\n",looptime,MINLOOPTIME);
            looptime = MINLOOPTIME;
        }
        if (looptime > MAXLOOPTIME) {
            fprintf(stderr,"CHUNKS_LOOP_MIN_TIME value too high (%"PRIu32") decreased to %u\n",looptime,MAXLOOPTIME);
            looptime = MAXLOOPTIME;
        }
        HashSteps = 1+((HASHSIZE)/looptime);
        HashCPS = cfg_getuint32("CHUNKS_LOOP_MAX_CPS",100000);
        if (HashCPS < MINCPS) {
            fprintf(stderr,"CHUNKS_LOOP_MAX_CPS value too low (%"PRIu32") increased to %u\n",HashCPS,MINCPS);
            HashCPS = MINCPS;
        }
        if (HashCPS > MAXCPS) {
            fprintf(stderr,"CHUNKS_LOOP_MAX_CPS value too high (%"PRIu32") decreased to %u\n",HashCPS,MAXCPS);
            HashCPS = MAXCPS;
        }
    }

    AcceptableDifference = cfg_getdouble("ACCEPTABLE_DIFFERENCE",0.05);
    if (AcceptableDifference<0.01) {
        AcceptableDifference = 0.01;
    }
    if (AcceptableDifference>0.1) {
        AcceptableDifference = 0.1;
    }

    jobshpos = 0;
    jobsrebalancecount = 0;
    starttime = CServerCore::get_time();
    jobsnorepbefore = starttime+ReplicationsDelayInit;
    chunk_do_jobs(NULL,JOBS_INIT,0.0,0.0);	// clear CChunkObj loop internal data

    CServerCore::getInstance()->reload_register(chunk_reload);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,1,0,chunk_jobs_main);

#endif
    return 1;
}
