#include "config.h"

#include <sys/types.h>
#ifdef HAVE_WRITEV
#include <sys/uio.h>
#endif
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include <syslog.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>

#include "DataPack.h"
#include "crc.h"
#include "strerr.h"
#include "pcqueue.h"
#include "sockets.h"
#include "CsOpStat.h"
#include "MasterComm.h"
#include "ReadWriteOpr.h"

#ifndef EDQUOT
#define EDQUOT ENOSPC
#endif

#define WORKERS 10

#define WCHASHSIZE 256
#define WCHASH(inode,indx) (((inode)*0xB239FB71+(indx)*193)%WCHASHSIZE)

#define IDHASHSIZE 256
#define IDHASH(inode) (((inode)*0xB239FB71)%IDHASHSIZE)

typedef struct cblock_s {
    uint8_t data[MFSBLOCKSIZE];	// modified only when writeid==0
    uint32_t chindx;	// chunk number
    uint16_t pos;		// block in chunk (0...1023) - never modified
    uint32_t writeid;	// 0 = not sent, >0 = block was sent (modified and accessed only when wchunk is locked)
    uint32_t from;		// first filled byte in data (modified only when writeid==0)
    uint32_t to;		// first not used byte in data (modified only when writeid==0)
    struct cblock_s *next,*prev;
} STCBlock;

typedef struct inodedata_s {
    uint32_t inode;
    uint64_t maxfleng;
    uint32_t cacheBlockCount;
    int status;
    uint16_t flushwaiting;
    uint16_t writewaiting;
    uint16_t lcnt;
    uint32_t trycnt;
    uint8_t waitingWorker;
    uint8_t inqueue;
    int pipe[2];
    STCBlock *datachAinHead,*datachAinTail;
    pthread_cond_t flushcond;	// wait for inqueue==0 (flush)
    pthread_cond_t writecond;	// wait for flushwaiting==0 (write)
    struct inodedata_s *next;
} STInodeData;

// static pthread_mutex_t fcblock;
static pthread_cond_t fcbcond;
static uint8_t fcbwaiting;
static STCBlock *s_cacheBlocks,*s_freecBlocksHead;
static uint32_t s_freeCacheBlocks;

static uint32_t s_MaxRetries;

static STInodeData **s_idHash;

static pthread_mutex_t glock;

#ifdef BUFFER_DEBUG
static pthread_t info_worker_th;
static uint32_t usedblocks;
#endif

static pthread_t dqueue_worker_th;
static pthread_t write_worker_th[WORKERS];

static void *jqueue,*dqueue;

#define TIMEDIFF(tv1,tv2) (((int64_t)((tv1).tv_sec-(tv2).tv_sec))*1000000LL+(int64_t)((tv1).tv_usec-(tv2).tv_usec))

#ifdef BUFFER_DEBUG
void* write_info_worker(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&glock);
        syslog(LOG_NOTICE,"used cache blocks: %"PRIu32,usedblocks);
        pthread_mutex_unlock(&glock);
        usleep(500000);
    }
}
#endif

/* glock: LOCKED */
void write_cb_release (STInodeData *id,STCBlock *cb) {
    //	pthread_mutex_lock(&fcblock);
    cb->next = s_freecBlocksHead;
    s_freecBlocksHead = cb;
    s_freeCacheBlocks++;
    id->cacheBlockCount--;
    if (fcbwaiting) {
        pthread_cond_signal(&fcbcond);
    }
#ifdef BUFFER_DEBUG
    usedblocks--;
#endif
    //	pthread_mutex_unlock(&fcblock);
}

/* glock: LOCKED */
STCBlock* write_cb_acquire(STInodeData *id)
{
    //	pthread_mutex_lock(&fcblock);
    fcbwaiting++;
    while (s_freecBlocksHead==NULL || id->cacheBlockCount>(s_freeCacheBlocks/3)) {
        pthread_cond_wait(&fcbcond,&glock);
    }
    fcbwaiting--;

    STCBlock *ret = s_freecBlocksHead;
    s_freecBlocksHead = ret->next;
    ret->chindx = 0;
    ret->pos = 0;
    ret->writeid = 0;
    ret->from = 0;
    ret->to = 0;
    ret->next = NULL;
    ret->prev = NULL;
    s_freeCacheBlocks--;
    id->cacheBlockCount++;
#ifdef BUFFER_DEBUG
    usedblocks++;
#endif
    //	pthread_mutex_unlock(&fcblock);
    return ret;
}


/* inode */

/* glock: LOCKED */
STInodeData* write_find_inodedata(uint32_t inode) {
    uint32_t idh = IDHASH(inode);
    for (STInodeData *id=s_idHash[idh] ; id ; id=id->next) {
        if (id->inode == inode) {
            return id;
        }
    }

    return NULL;
}

/* glock: LOCKED */
STInodeData* write_get_inodedata(uint32_t inode) {
    uint32_t idh = IDHASH(inode);
    STInodeData *id;

    for (id=s_idHash[idh] ; id ; id=id->next) {
        if (id->inode == inode) {
            return id;
        }
    }

    int pfd[2];
    if (pipe(pfd)<0) {
        syslog(LOG_WARNING,"pipe error: %s",strerr(errno));
        return NULL;
    }

    id = (STInodeData*)malloc(sizeof(STInodeData));
    id->inode = inode;
    id->cacheBlockCount = 0;
    id->maxfleng = 0;
    id->status = 0;
    id->trycnt = 0;
    id->pipe[0] = pfd[0];
    id->pipe[1] = pfd[1];
    id->datachAinHead = NULL;
    id->datachAinTail = NULL;
    id->waitingWorker = 0;
    id->inqueue = 0;
    id->flushwaiting = 0;
    id->writewaiting = 0;
    id->lcnt = 0;
    pthread_cond_init(&(id->flushcond),NULL);
    pthread_cond_init(&(id->writecond),NULL);
    id->next = s_idHash[idh];
    s_idHash[idh] = id;

    return id;
}

/* glock: LOCKED */
void write_free_inodedata(STInodeData *fid) {
    uint32_t idh = IDHASH(fid->inode);
    STInodeData *id,**idp = &(s_idHash[idh]);
    while ((id=*idp)) {
        if (id==fid) {
            *idp = id->next;
            pthread_cond_destroy(&(id->flushcond));
            pthread_cond_destroy(&(id->writecond));
            close(id->pipe[0]);
            close(id->pipe[1]);
            free(id);
            return;
        }
        idp = &(id->next);
    }
}

/* queues */

/* glock: UNUSED */
void write_delayed_enqueue(STInodeData *id,uint32_t cnt) {
    struct timeval tv;
    if (cnt>0) {
        gettimeofday(&tv,NULL);
        queue_put(dqueue,tv.tv_sec,tv.tv_usec,(uint8_t*)id,cnt);
    } else {
        queue_put(jqueue,0,0,(uint8_t*)id,0);
    }
}

/* glock: UNUSED */
void write_enqueue(STInodeData *id) {
    queue_put(jqueue,0,0,(uint8_t*)id,0);
}

/* worker thread | glock: UNUSED */
void* write_dqueue_worker(void *arg) {
    struct timeval tv;
    uint32_t sec,usec,cnt;
    uint8_t *id;
    (void)arg;
    for (;;) {
        queue_get(dqueue,&sec,&usec,&id,&cnt);
        if (id==NULL) {
            return NULL;
        }

        gettimeofday(&tv,NULL);
        if ((uint32_t)(tv.tv_usec) < usec) {
            tv.tv_sec--;
            tv.tv_usec += 1000000;
        }

        if ((uint32_t)(tv.tv_sec) < sec) {
            // time went backward !!!
            sleep(1);
        } else if ((uint32_t)(tv.tv_sec) == sec) {
            usleep(1000000-(tv.tv_usec-usec));
        }
        cnt--;
        if (cnt>0) {
            gettimeofday(&tv,NULL);
            queue_put(dqueue,tv.tv_sec,tv.tv_usec,(uint8_t*)id,cnt);
        } else {
            queue_put(jqueue,0,0,id,0);
        }
    }

    return NULL;
}

/* glock: UNLOCKED */
void write_job_end(STInodeData *id,int status,uint32_t delay) {
    STCBlock *cb,*fcb;

    pthread_mutex_lock(&glock);
    if (status) {
        errno = status;
        syslog(LOG_WARNING,"error writing file number %"PRIu32": %s",id->inode,strerr(errno));
        id->status = status;
    }
    status = id->status;

    if (id->datachAinHead && status==0) {	// still have some work to do
        // reset write id
        for (cb=id->datachAinHead ; cb ; cb=cb->next) {
            cb->writeid = 0;
        }
        if (delay==0) {
            id->trycnt=0;	// on good write reset try counter
        }
        write_delayed_enqueue(id,delay);
    } else {	// no more work or error occured
        // if this is an error then release all data blocks
        cb = id->datachAinHead;
        while (cb) {
            fcb = cb;
            cb = cb->next;
            write_cb_release(id,fcb);
        }
        id->datachAinHead=NULL;
        id->inqueue=0;

        if (id->flushwaiting>0) {
            pthread_cond_broadcast(&(id->flushcond));
        }
    }
    pthread_mutex_unlock(&glock);
}

/* main working thread | glock:UNLOCKED */
void* write_worker(void *arg)
{
    uint32_t z1,z2,z3;
    uint8_t *data;
    int fd;
    int i;
    struct pollfd pfd[2];
    uint32_t sent,rcvd;
    uint8_t recvbuff[21];
    uint8_t sendbuff[32];
#ifdef HAVE_WRITEV
    struct iovec siov[2];
#endif
    uint8_t pipebuff[1024];
    uint8_t *wptr;
    const uint8_t *rptr;

    uint32_t reccmd, recleng;
    uint64_t recchunkid;
    uint32_t recwriteid;
    uint8_t recstatus;

#ifdef WORKER_DEBUG
    uint32_t partialblocks;
    uint32_t bytessent;
    char debugchain[200];
    uint32_t cl;
#endif

    const uint8_t *cp,*cpe;
    uint32_t chainip[10];
    uint16_t chainport[10];

    uint32_t chindx;
    uint32_t ip;
    uint16_t port;
    uint32_t srcip;
    uint64_t mfleng;
    uint64_t maxwroffset;
    uint64_t chunkid;
    uint32_t version;
    uint32_t nextWriteId;

    const uint8_t *chain;
    uint32_t chainsize;
    const uint8_t *csdata;
    uint32_t csdatasize;

    uint8_t westatus, wrstatus;
    int status;
    uint8_t waitForStatus;
    uint8_t havedata;
    uint8_t jobs;
    struct timeval start,now,lastrcvd,lrdiff;

    uint8_t cnt;

    STInodeData *id;
    STCBlock *cb,*rcb;

    uint16_t usChainElems = 0;

    (void)arg;
    for (;;)
    {
        for (cnt=0 ; cnt<usChainElems ; cnt++) {
            csdb_writedec(chainip[cnt],chainport[cnt]);
        }
        usChainElems=0;

        // get next job
        queue_get(jqueue,&z1,&z2,&data,&z3);
        if (data==NULL) {
            return NULL;
        }
        id = (STInodeData*)data;

        pthread_mutex_lock(&glock);
        if (id->datachAinHead) {
            chindx = id->datachAinHead->chindx;
            status = id->status;
        } else {
            syslog(LOG_WARNING,"writeworker got inode with no data to write !!!");
            chindx = 0;
            status = EINVAL;	// this should never happen, so status is not important - just anything
        }
        pthread_mutex_unlock(&glock);

        if (status) {
            write_job_end(id,status,0);
            continue;
        }

        // syslog(LOG_NOTICE,"file: %"PRIu32", index: %"PRIu16" - debug1",id->inode,chindx);
        // get chunk data from master
        wrstatus = fs_writechunk(id->inode,chindx,&mfleng,&chunkid,&version,&csdata,&csdatasize);
        if (wrstatus!=STATUS_OK) {
            syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32" - fs_writechunk returns status: %s",id->inode,chindx,mfsstrerr(wrstatus));
            if (wrstatus!=ERROR_LOCKED) {
                if (wrstatus==ERROR_ENOENT) {
                    write_job_end(id,EBADF,0);
                } else if (wrstatus==ERROR_QUOTA) {
                    write_job_end(id,EDQUOT,0);
                } else if (wrstatus==ERROR_NOSPACE) {
                    write_job_end(id,ENOSPC,0);
                } else {
                    id->trycnt++;
                    if (id->trycnt>=s_MaxRetries) {
                        if (wrstatus==ERROR_NOCHUNKSERVERS) {
                            write_job_end(id,ENOSPC,0);
                        } else {
                            write_job_end(id,EIO,0);
                        }
                    } else {
                        write_delayed_enqueue(id,1+((id->trycnt<30)?(id->trycnt/3):10));
                    }
                }
            } else {
                write_delayed_enqueue(id,1+((id->trycnt<30)?(id->trycnt/3):10));
            }
            continue;	// get next job
        }

        if (csdata==NULL || csdatasize==0) {
            syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32" - there are no valid copies",id->inode,chindx,chunkid,version);
            id->trycnt+=6;
            if (id->trycnt>=s_MaxRetries) {
                write_job_end(id,ENXIO,0);
            } else {
                write_delayed_enqueue(id,60);
            }
            continue;
        }

        cp = csdata;
        cpe = csdata+csdatasize;
        while (cp<cpe && usChainElems<10) {
            chainip[usChainElems] = get32bit(&cp);
            chainport[usChainElems] = get16bit(&cp);
            csdb_writeinc(chainip[usChainElems],chainport[usChainElems]);
            usChainElems++;
        }

        chain = csdata;
        ip = get32bit(&chain);
        port = get16bit(&chain);
        chainsize = csdatasize-6;
        gettimeofday(&start,NULL);

        // make connection to cs
        srcip = fs_getsrcip();
        cnt=0;
        while (cnt<10) {
            fd = tcpSocket();
            if (fd<0) {
                syslog(LOG_WARNING,"can't create tcp socket: %s",strerr(errno));
                break;
            }
            if (srcip) {
                if (tcpNumBind(fd,srcip,0)<0) {
                    syslog(LOG_WARNING,"can't bind socket to given ip: %s",strerr(errno));
                    tcpClose(fd);
                    fd=-1;
                    break;
                }
            }
            if (tcpNumToConnect(fd,ip,port,(cnt%2)?(300*(1<<(cnt>>1))):(200*(1<<(cnt>>1))))<0) {
                cnt++;
                if (cnt>=10) {
                    syslog(LOG_WARNING,"can't connect to (%08"PRIX32":%"PRIu16"): %s",ip,port,strerr(errno));
                }
                tcpClose(fd);
                fd=-1;
            } else {
                cnt=10;
            }
        }//end while

        if (fd<0) {
            fs_writeend(chunkid,id->inode,0);
            id->trycnt++;
            if (id->trycnt>=s_MaxRetries) {
                write_job_end(id,EIO,0);
            } else {
                write_delayed_enqueue(id,1+((id->trycnt<30)?(id->trycnt/3):10));
            }
            continue;
        }

        if (tcpNoDelay(fd)<0) {
            syslog(LOG_WARNING,"can't set TCP_NODELAY: %s",strerr(errno));
        }

#ifdef WORKER_DEBUG
        partialblocks=0;
        bytessent=0;
#endif
        nextWriteId=1;

        pfd[0].fd = fd;
        pfd[1].fd = id->pipe[0];
        rcvd = sent = 0;
        waitForStatus=1;
        havedata=1;
        wptr = sendbuff;
        put32bit(&wptr,CLTOCS_WRITE);
        put32bit(&wptr,12+chainsize);
        put64bit(&wptr,chunkid);
        put32bit(&wptr,version);
        // debug:	syslog(LOG_NOTICE,"writeworker: init packet prepared");
        cb = NULL;

        status = 0;
        wrstatus = STATUS_OK;

        lastrcvd.tv_sec = 0;

        do {
            jobs = queue_isempty(jqueue)?0:1;
            gettimeofday(&now,NULL);

            if (lastrcvd.tv_sec==0) {
                lastrcvd = now;
            } else {
                lrdiff = now;
                if (lrdiff.tv_usec<lastrcvd.tv_usec) {
                    lrdiff.tv_sec--;
                    lrdiff.tv_usec+=1000000;
                }
                lrdiff.tv_sec -= lastrcvd.tv_sec;
                lrdiff.tv_usec -= lastrcvd.tv_usec;
                if (lrdiff.tv_sec>=2) {
                    syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32" - writeworker: connection with (%08"PRIX32":%"PRIu16") was timed out (unfinished writes: %"PRIu8"; try counter: %"PRIu32")",id->inode,chindx,chunkid,version,ip,port,waitForStatus,id->trycnt+1);
                    break;
                }
            }

            if (now.tv_usec<start.tv_usec) {
                now.tv_sec--;
                now.tv_usec+=1000000;
            }
            now.tv_sec -= start.tv_sec;
            now.tv_usec -= start.tv_usec;

            if (havedata==0 && now.tv_sec<(jobs?5:25) && waitForStatus<15) {
                pthread_mutex_lock(&glock);
                if (cb==NULL) {
                    if (id->datachAinHead) {
                        if (id->datachAinHead->to-id->datachAinHead->from==MFSBLOCKSIZE || waitForStatus<=1) {
                            cb = id->datachAinHead;
                            havedata=1;
                        }
                    }
                } else {
                    if (cb->next) {
                        if (cb->next->chindx==chindx) {
                            if (cb->next->to-cb->next->from==MFSBLOCKSIZE || waitForStatus<=1) {
                                cb = cb->next;
                                havedata=1;
                            }
                        }
                    } else {
                        id->waitingWorker=1;
                    }
                }

                if (havedata==1) {
                    cb->writeid = nextWriteId++;
                    waitForStatus++;
                    wptr = sendbuff;
                    put32bit(&wptr,CLTOCS_WRITE_DATA);
                    put32bit(&wptr,24+(cb->to-cb->from));
                    put64bit(&wptr,chunkid);
                    put32bit(&wptr,cb->writeid);
                    put16bit(&wptr,cb->pos);
                    put16bit(&wptr,cb->from);
                    put32bit(&wptr,cb->to-cb->from);
                    put32bit(&wptr,mycrc32(0,cb->data+cb->from,cb->to-cb->from));
#ifdef WORKER_DEBUG
                    if (cb->to-cb->from<MFSBLOCKSIZE) {
                        partialblocks++;
                    }
                    bytessent+=(cb->to-cb->from);
#endif
                    sent=0;
                }
                pthread_mutex_unlock(&glock);
            }

            pfd[0].events = POLLIN | (havedata?POLLOUT:0);
            pfd[0].revents = 0;
            pfd[1].events = POLLIN;
            pfd[1].revents = 0;
            if (poll(pfd,2,100)<0) { /* correct timeout - in msec */
                syslog(LOG_WARNING,"writeworker: poll error: %s",strerr(errno));
                status=EIO;
                break;
            }

            pthread_mutex_lock(&glock);	// make helgrind happy
            id->waitingWorker=0;
            pthread_mutex_unlock(&glock);	// make helgrind happy

            if (pfd[1].revents&POLLIN) {	// used just to break poll - so just read all data from pipe to empty it
                i = read(id->pipe[0],pipebuff,1024);
                if (i<0) { // mainly to make happy static code analyzers
                    syslog(LOG_NOTICE,"read pipe error: %s",strerr(errno));
                }
            }

            if (pfd[0].revents&POLLIN) {
                i = read(fd,recvbuff+rcvd,21-rcvd);
                if (i==0) { 	// connection reset by peer
                    syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32" - writeworker: connection with (%08"PRIX32":%"PRIu16") was reset by peer (unfinished writes: %"PRIu8"; try counter: %"PRIu32")",id->inode,chindx,chunkid,version,ip,port,waitForStatus,id->trycnt+1);
                    status=EIO;
                    break;
                }

                gettimeofday(&lastrcvd,NULL);
                rcvd+=i;
                // do not accept ANTOAN_UNKNOWN_COMMAND and ANTOAN_BAD_COMMAND_SIZE here - only ANTOAN_NOP
                if (rcvd>=8 && recvbuff[7]==0 && recvbuff[6]==0 && recvbuff[5]==0 && recvbuff[4]==0 
                    && recvbuff[3]==0 && recvbuff[2]==0 && recvbuff[1]==0 && recvbuff[0]==0) {	// ANTOAN_NOP packet received - skip it
                    if (rcvd>8) {
                        memmove(recvbuff,recvbuff+8,rcvd-8);
                        rcvd-=8;
                    }
                }

                if (rcvd==21) {
                    rptr = recvbuff;
                    reccmd = get32bit(&rptr);
                    recleng = get32bit(&rptr);
                    recchunkid = get64bit(&rptr);
                    recwriteid = get32bit(&rptr);
                    recstatus = get8bit(&rptr);

                    if (reccmd!=CSTOCL_WRITE_STATUS ||  recleng!=13) {
                        syslog(LOG_WARNING,"writeworker: got unrecognized packet from chunkserver (cmd:%"PRIu32",leng:%"PRIu32")",reccmd,recleng);
                        status=EIO;
                        break;
                    }

                    if (recchunkid!=chunkid) {
                        syslog(LOG_WARNING,"writeworker: got unexpected packet (expected chunkdid:%"PRIu64",packet chunkid:%"PRIu64")",chunkid,recchunkid);
                        status=EIO;
                        break;
                    }

                    if (recstatus!=STATUS_OK) {
                        syslog(LOG_WARNING,"writeworker: write error: %s",mfsstrerr(recstatus));
                        wrstatus=recstatus;
                        break;
                    }

                    if (recwriteid>0) {
                        pthread_mutex_lock(&glock);
                        for (rcb = id->datachAinHead ; rcb && rcb->writeid!=recwriteid ; rcb=rcb->next) {}
                        if (rcb==NULL) {
                            syslog(LOG_WARNING,"writeworker: got unexpected status (writeid:%"PRIu32")",recwriteid);
                            pthread_mutex_unlock(&glock);
                            status=EIO;
                            break;
                        }

                        if (rcb==cb) {	// current block
                            if (havedata) {	// got status ok before all data had been sent - error
                                syslog(LOG_WARNING,"writeworker: got status OK before all data have been sent");
                                pthread_mutex_unlock(&glock);
                                status=EIO;
                                break;
                            } else {
                                cb = NULL;
                            }
                        }

                        if (rcb->prev) {
                            rcb->prev->next = rcb->next;
                        } else {
                            id->datachAinHead = rcb->next;
                        }
                        if (rcb->next) {
                            rcb->next->prev = rcb->prev;
                        } else {
                            id->datachAinTail = rcb->prev;
                        }

                        maxwroffset = (((uint64_t)(chindx))<<MFSCHUNKBITS)+(((uint32_t)(rcb->pos))<<MFSBLOCKBITS)+rcb->to;
                        if (maxwroffset>mfleng) {
                            mfleng=maxwroffset;
                        }
                        write_cb_release(id,rcb);
                        pthread_mutex_unlock(&glock);
                    }
                    waitForStatus--;
                    rcvd=0;
                }
            }//end if

            if (havedata && (pfd[0].revents&POLLOUT)) {
                if (cb==NULL) {	// havedata==1 && cb==NULL means sending first packet (CLTOCS_WRITE)
                    if (sent<20) {
#ifdef HAVE_WRITEV
                        if (chainsize>0) {
                            siov[0].iov_base = (void*)(sendbuff+sent);
                            siov[0].iov_len = 20-sent;
                            siov[1].iov_base = (void*)chain;	// discard const (safe - because it's used in writev)
                            siov[1].iov_len = chainsize;
                            i = writev(fd,siov,2);
                        } else {
#endif
                            i = write(fd,sendbuff+sent,20-sent);
#ifdef HAVE_WRITEV
                        }
#endif
                    } else {
                        i = write(fd,chain+(sent-20),chainsize-(sent-20));
                    }
                    if (i<0) {
                        syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32" - writeworker: connection with (%08"PRIX32":%"PRIu16") was reset by peer (unfinished writes: %"PRIu8"; try counter: %"PRIu32")",id->inode,chindx,chunkid,version,ip,port,waitForStatus,id->trycnt+1);
                        status=EIO;
                        break;
                    }
                    sent+=i;
                    if (sent==20+chainsize) {
                        havedata=0;
                    }
                } else {
                    if (sent<32) {
#ifdef HAVE_WRITEV
                        siov[0].iov_base = (void*)(sendbuff+sent);
                        siov[0].iov_len = 32-sent;
                        siov[1].iov_base = (void*)(cb->data+cb->from);
                        siov[1].iov_len = cb->to-cb->from;
                        i = writev(fd,siov,2);
#else
                        i = write(fd,sendbuff+sent,32-sent);
#endif
                    } else {
                        i = write(fd,cb->data+cb->from+(sent-32),cb->to-cb->from-(sent-32));
                    }

                    if (i<0) {
                        syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32" - writeworker: connection with (%08"PRIX32":%"PRIu16") was reset by peer (unfinished writes: %"PRIu8"; try counter: %"PRIu32")",id->inode,chindx,chunkid,version,ip,port,waitForStatus,id->trycnt+1);
                        status=EIO;
                        break;
                    }
                    sent+=i;
                    if (sent==32+cb->to-cb->from) {
                        havedata=0;
                    }
                }//end if
            }//end if

        } while (waitForStatus>0 && now.tv_sec<(jobs?10:30));

        tcpClose(fd);

#ifdef WORKER_DEBUG
        gettimeofday(&now,NULL);
        if (now.tv_usec<start.tv_usec) {
            now.tv_sec--;
            now.tv_usec+=1000000;
        }
        now.tv_sec -= start.tv_sec;
        now.tv_usec -= start.tv_usec;

        cl=0;
        for (cnt=0 ; cnt<usChainElems ; cnt++) {
            cl+=snprintf(debugchain+cl,200-cl,"%u.%u.%u.%u:%u->",(chainip[cnt]>>24)&255,(chainip[cnt]>>16)&255,(chainip[cnt]>>8)&255,chainip[cnt]&255,chainport[cnt]);
        }
        if (cl>=2) {
            debugchain[cl-2]='\0';
        }
        syslog(LOG_NOTICE,"worker %lu sent %"PRIu32" blocks (%"PRIu32" partial) of chunk %016"PRIX64"_%08"PRIX32", received status for %"PRIu32" blocks (%"PRIu32" lost), bw: %.6lfMB ( %"PRIu32" B / %.0lf us ), chain: %s",(unsigned long)arg,nextWriteId-1,partialblocks,chunkid,version,nextWriteId-1-waitForStatus,waitForStatus,(double)bytessent/((double)(now.tv_sec)*1000000+(double)(now.tv_usec)),bytessent,((double)(now.tv_sec)*1000000+(double)(now.tv_usec)),debugchain);
#endif

        for (cnt=0 ; cnt<10 ; cnt++) {
            westatus = fs_writeend(chunkid,id->inode,mfleng);
            if (westatus!=STATUS_OK) {
                usleep(100000+(10000<<cnt));
            } else {
                break;
            }
        }

        if (westatus!=STATUS_OK) {
            write_job_end(id,ENXIO,0);
        } else if (status!=0 || wrstatus!=STATUS_OK) {
            if (wrstatus!=STATUS_OK) {	// convert MFS status to OS errno
                if (wrstatus==ERROR_NOSPACE) {
                    status=ENOSPC;
                } else {
                    status=EIO;
                }
            }
            id->trycnt++;
            if (id->trycnt>=s_MaxRetries) {
                write_job_end(id,status,0);
            } else {
                write_job_end(id,0,1+((id->trycnt<30)?(id->trycnt/3):10));
            }
        } else {
            read_inode_ops(id->inode);
            write_job_end(id,0,0);
        }
    }
}

/* API | glock: INITIALIZED,UNLOCKED */
void write_data_init (uint32_t cachesize,uint32_t retries)
{
    uint32_t cacheBlockCount = (cachesize/MFSBLOCKSIZE);
    uint32_t i;
    pthread_attr_t thattr;

    s_MaxRetries = retries;
    if (cacheBlockCount<10) {
        cacheBlockCount=10;
    }
    pthread_mutex_init(&glock,NULL);

    pthread_cond_init(&fcbcond,NULL);
    fcbwaiting=0;

    s_cacheBlocks = (STCBlock*)malloc(sizeof(STCBlock)*cacheBlockCount);
    for (i=0 ; i<cacheBlockCount-1 ; i++) {
        s_cacheBlocks[i].next = s_cacheBlocks+(i+1);
    }
    s_cacheBlocks[cacheBlockCount-1].next = NULL;
    s_freecBlocksHead = s_cacheBlocks;
    s_freeCacheBlocks = cacheBlockCount;

    s_idHash = (STInodeData**)malloc(sizeof(STInodeData*)*IDHASHSIZE);
    for (i=0 ; i<IDHASHSIZE ; i++) {
        s_idHash[i]=NULL;
    }

    dqueue = queue_new(0);
    jqueue = queue_new(0);

    pthread_attr_init(&thattr);
    pthread_attr_setstacksize(&thattr,0x100000);
    pthread_create(&dqueue_worker_th,&thattr,write_dqueue_worker,NULL);
#ifdef BUFFER_DEBUG
    pthread_create(&info_worker_th,&thattr,write_info_worker,NULL);
#endif
    for (i=0 ; i<WORKERS ; i++) {
        pthread_create(write_worker_th+i,&thattr,write_worker,(void*)(unsigned long)(i));
    }
    pthread_attr_destroy(&thattr);
}

void write_data_term(void) {
    uint32_t i;
    STInodeData *id,*idn;

    queue_put(dqueue,0,0,NULL,0);
    for (i=0 ; i<WORKERS ; i++) {
        queue_put(jqueue,0,0,NULL,0);
    }
    for (i=0 ; i<WORKERS ; i++) {
        pthread_join(write_worker_th[i],NULL);
    }
    pthread_join(dqueue_worker_th,NULL);
    queue_delete(dqueue);
    queue_delete(jqueue);

    for (i=0 ; i<IDHASHSIZE ; i++) {
        for (id = s_idHash[i] ; id ; id = idn) {
            idn = id->next;
            pthread_cond_destroy(&(id->flushcond));
            pthread_cond_destroy(&(id->writecond));
            close(id->pipe[0]);
            close(id->pipe[1]);
            free(id);
        }
    }
    free(s_idHash);
    free(s_cacheBlocks);
    pthread_cond_destroy(&fcbcond);
    pthread_mutex_destroy(&glock);
}

/* glock: LOCKED */
int write_cb_expand(STCBlock *cb,uint32_t from,uint32_t to,const uint8_t *data) {
    if (cb->writeid>0 || from>cb->to || to<cb->from) {	// can't expand
        return -1;
    }
    memcpy(cb->data+from,data,to-from);
    if (from<cb->from) {
        cb->from = from;
    }
    if (to>cb->to) {
        cb->to = to;
    }
    return 0;
}

/* glock: UNLOCKED */
int write_block(STInodeData *id,uint32_t chindx,uint16_t pos,uint32_t from,uint32_t to,const uint8_t *data)
{
    STCBlock *cb;

    pthread_mutex_lock(&glock);
    for (cb=id->datachAinTail ; cb ; cb=cb->prev) {
        if (cb->pos==pos && cb->chindx==chindx) {
            if (write_cb_expand(cb,from,to,data)==0) {
                pthread_mutex_unlock(&glock);
                return 0;
            } else {
                break;
            }
        }
    }

    cb = write_cb_acquire(id);
    //	syslog(LOG_NOTICE,"write_block: acquired new cache block");
    cb->chindx = chindx;
    cb->pos = pos;
    cb->from = from;
    cb->to = to;
    memcpy(cb->data+from,data,to-from);
    cb->prev = id->datachAinTail;
    cb->next = NULL;
    if (id->datachAinTail!=NULL) {
        id->datachAinTail->next = cb;
    } else {
        id->datachAinHead = cb;
    }
    id->datachAinTail = cb;

    if (id->inqueue) {
        if (id->waitingWorker) {
            if (write(id->pipe[1]," ",1)!=1) {
                syslog(LOG_ERR,"can't write to pipe !!!");
            }
            id->waitingWorker=0;
        }
    } else {
        id->inqueue=1;
        write_enqueue(id);
    }
    pthread_mutex_unlock(&glock);

    return 0;
}

/* API | glock: UNLOCKED */
int write_data(void *vid,uint64_t offset,uint32_t size,const uint8_t *data) 
{
    STInodeData *id = (STInodeData*)vid;
    if (id==NULL) {
        return EIO;
    }

    pthread_mutex_lock(&glock);
    int status = id->status;
    if (status==0) {
        if (offset+size>id->maxfleng) {	// move fleng
            id->maxfleng = offset+size;
        }
        id->writewaiting++;
        while (id->flushwaiting>0) {
            pthread_cond_wait(&(id->writecond),&glock);
        }
        id->writewaiting--;
    }
    pthread_mutex_unlock(&glock);
    if (status!=0) {
        return status;
    }

    uint32_t chindx = offset>>MFSCHUNKBITS;
    uint16_t pos = (offset&MFSCHUNKMASK)>>MFSBLOCKBITS;
    uint32_t from = offset&MFSBLOCKMASK;

    while (size>0) {
        if (size>MFSBLOCKSIZE-from) {
            if (write_block(id,chindx,pos,from,MFSBLOCKSIZE,data)<0) {
                return EIO;
            }
            size -= (MFSBLOCKSIZE-from);
            data += (MFSBLOCKSIZE-from);
            from = 0;
            pos++;
            if (pos==1024) {
                pos = 0;
                chindx++;
            }
        } else {
            if (write_block(id,chindx,pos,from,from+size,data)<0) {
                return EIO;
            }
            size = 0;
        }
    }

    return 0;
}

/* API | glock: UNLOCKED */
void* write_data_new(uint32_t inode) {
    pthread_mutex_lock(&glock);
    STInodeData* id = write_get_inodedata(inode);
    if (id==NULL) {
        pthread_mutex_unlock(&glock);
        return NULL;
    }
    id->lcnt++;
    pthread_mutex_unlock(&glock);

    return id;
}

int write_data_flush(void *vid) {
    STInodeData* id = (STInodeData*)vid;
    if (id==NULL) {
        return EIO;
    }

    pthread_mutex_lock(&glock);
    id->flushwaiting++;
    while (id->inqueue) {
        pthread_cond_wait(&(id->flushcond),&glock);
    }
    id->flushwaiting--;
    if (id->flushwaiting==0 && id->writewaiting>0) {
        pthread_cond_broadcast(&(id->writecond));
    }

    int ret = id->status;
    if (id->lcnt==0 && id->inqueue==0 && id->flushwaiting==0 && id->writewaiting==0) {
        write_free_inodedata(id);
    }
    pthread_mutex_unlock(&glock);

    return ret;
}

uint64_t write_data_getmaxfleng(uint32_t inode) {
    uint64_t maxfleng;
    pthread_mutex_lock(&glock);
    STInodeData* id = write_find_inodedata(inode);
    if (id) {
        maxfleng = id->maxfleng;
    } else {
        maxfleng = 0;
    }
    pthread_mutex_unlock(&glock);
    return maxfleng;
}

/* API | glock: UNLOCKED */
int write_data_flush_inode(uint32_t inode) {
    pthread_mutex_lock(&glock);
    STInodeData* id = write_find_inodedata(inode);
    if (id==NULL) {
        pthread_mutex_unlock(&glock);
        return 0;
    }
    id->flushwaiting++;
    while (id->inqueue) {
        pthread_cond_wait(&(id->flushcond),&glock);
    }
    id->flushwaiting--;
    if (id->flushwaiting==0 && id->writewaiting>0) {
        pthread_cond_broadcast(&(id->writecond));
    }
    int ret = id->status;
    if (id->lcnt==0 && id->inqueue==0 && id->flushwaiting==0 && id->writewaiting==0) {
        write_free_inodedata(id);
    }
    pthread_mutex_unlock(&glock);

    return ret;
}

/* API | glock: UNLOCKED */
int write_data_end(void *vid) {
    STInodeData* id = (STInodeData*)vid;
    if (id==NULL) {
        return EIO;
    }
    pthread_mutex_lock(&glock);
    id->flushwaiting++;
    while (id->inqueue) {
        //		syslog(LOG_NOTICE,"write_end: wait ...");
        pthread_cond_wait(&(id->flushcond),&glock);
        //		syslog(LOG_NOTICE,"write_end: woken up");
    }
    id->flushwaiting--;
    if (id->flushwaiting==0 && id->writewaiting>0) {
        pthread_cond_broadcast(&(id->writecond));
    }
    int ret = id->status;
    id->lcnt--;
    if (id->lcnt==0 && id->inqueue==0 && id->flushwaiting==0 && id->writewaiting==0) {
        write_free_inodedata(id);
    }
    pthread_mutex_unlock(&glock);

    return ret;
}
