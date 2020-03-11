#include "config.h"

#include <sys/time.h>
#include <time.h>
#include <syslog.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>

#include "sockets.h"
#include "strerr.h"
#include "DataPack.h"
#include "MasterComm.h"
#include "ClientComm.h"
#include "CsOpStat.h"
#include "ChunkFileCache.h"

#define USECTICK 333333

#define REFRESHTICKS 15
#define CLOSEDELAYTICKS 3

#define MAPBITS 10
#define MAPSIZE (1<<(MAPBITS))
#define MAPMASK (MAPSIZE-1)
#define MAPINDX(inode) (inode&MAPMASK)

typedef struct _STReadRec {
	uint8_t *rBuff;			// this->locked
	uint32_t rBuffSize;		// this->locked
	uint32_t inode;			// this->locked
	uint64_t fleng;			// this->locked
	uint32_t indx;			// this->locked
	uint64_t chunkid;		// this->locked
	uint32_t version;		// this->locked
	uint32_t ip;			// this->locked
	uint16_t port;			// this->locked
	int fd;				    // this->locked
	uint8_t refcnt;			// glock
	uint8_t noaccesscnt;	// glock
	uint8_t valid;			// glock
	uint8_t locked;			// glock
	uint16_t waiting;		// glock
	pthread_cond_t cond;		// glock
	struct _STReadRec *next;	// glock
	struct _STReadRec *mapnext;	// glock
} STReadRec;

static STReadRec *s_RdInodeMap[MAPSIZE];
static STReadRec *s_pRdHead=NULL;
static pthread_t pthid;
static pthread_mutex_t glock;

static uint32_t s_MaxRetries;
static uint8_t rterm;

#define TIMEDIFF(tv1,tv2) (((int64_t)((tv1).tv_sec-(tv2).tv_sec))*1000000LL+(int64_t)((tv1).tv_usec-(tv2).tv_usec))

void* read_data_delayed_ops(void *arg)
{
	STReadRec *rrec,**rrecp;
	STReadRec **rrecmap;
	(void)arg;
	for (;;) {
		pthread_mutex_lock(&glock);
		if (rterm) {
			pthread_mutex_unlock(&glock);
			return NULL;
		}

		rrecp = &s_pRdHead;
		while ((rrec=*rrecp)!=NULL) {
			if (rrec->refcnt<REFRESHTICKS) {
				rrec->refcnt++;
			}

			if (rrec->locked==0) {
				if (rrec->valid==0) {
					pthread_cond_destroy(&(rrec->cond));
					*rrecp = rrec->next;
					rrecmap = &(s_RdInodeMap[MAPINDX(rrec->inode)]);
					while (*rrecmap) {
						if ((*rrecmap)==rrec) {
							*rrecmap = rrec->mapnext;
						} else {
							rrecmap = &((*rrecmap)->mapnext);
						}
					}
					free(rrec);
				} else {
					if (rrec->fd>=0) {
						if (rrec->noaccesscnt==CLOSEDELAYTICKS) {
							csdb_readdec(rrec->ip,rrec->port);
							tcpClose(rrec->fd);
							rrec->fd=-1;
						} else {
							rrec->noaccesscnt++;
						}
					}
					rrecp = &(rrec->next);
				}
			} else {
				rrecp = &(rrec->next);
			}
		}
		pthread_mutex_unlock(&glock);
		usleep(USECTICK);
	}
}

void* read_data_new(uint32_t inode) 
{
	STReadRec *rrec = (STReadRec*)malloc(sizeof(STReadRec));
	rrec->rBuff = NULL;
	rrec->rBuffSize = 0;
	rrec->inode = inode;
	rrec->fleng = 0;
	rrec->indx = 0;
	rrec->chunkid = 0;
	rrec->version = 0;
	rrec->fd = -1;
	rrec->ip = 0;
	rrec->port = 0;
	rrec->refcnt = 0;
	rrec->noaccesscnt = 0;
	rrec->valid = 1;
	rrec->waiting = 0;
	rrec->locked = 0;

	pthread_cond_init(&(rrec->cond),NULL);

	pthread_mutex_lock(&glock);
	rrec->next = s_pRdHead;
	s_pRdHead = rrec;
	rrec->mapnext = s_RdInodeMap[MAPINDX(inode)];
	s_RdInodeMap[MAPINDX(inode)] = rrec;
	pthread_mutex_unlock(&glock);

	return rrec;
}

void read_data_end(void* rr)
{
	STReadRec *rrec = (STReadRec*)rr;

	pthread_mutex_lock(&glock);
	rrec->waiting++;
	while (rrec->locked) {
		pthread_cond_wait(&(rrec->cond),&glock);
	}
	rrec->waiting--;
	rrec->locked = 1;
	rrec->valid = 0;
	pthread_mutex_unlock(&glock);

	if (rrec->fd>=0) {
		csdb_readdec(rrec->ip,rrec->port);
		tcpClose(rrec->fd);
		rrec->fd=-1;
	}
	if (rrec->rBuff!=NULL) {
		free(rrec->rBuff);
		rrec->rBuff=NULL;
	}

	pthread_mutex_lock(&glock);
	if (rrec->waiting) {
		pthread_cond_signal(&(rrec->cond));
	}
	rrec->locked = 0;
	pthread_mutex_unlock(&glock);
}

void read_data_init(uint32_t retries) 
{
	rterm = 0;
	for (uint32_t i=0 ; i<MAPSIZE ; i++) {
		s_RdInodeMap[i]=NULL;
	}
	s_MaxRetries=retries;

	pthread_mutex_init(&glock,NULL);
    pthread_attr_t thattr;
	pthread_attr_init(&thattr);
	pthread_attr_setstacksize(&thattr,0x100000);
	pthread_create(&pthid,&thattr,read_data_delayed_ops,NULL);
	pthread_attr_destroy(&thattr);
}

void read_data_term(void)
{
	pthread_mutex_lock(&glock);
	rterm = 1;
	pthread_mutex_unlock(&glock);
	pthread_join(pthid,NULL);
	pthread_mutex_destroy(&glock);

	STReadRec *rr,*rrn;
	for (uint32_t i=0 ; i<MAPSIZE ; i++) {
		for (rr = s_RdInodeMap[i] ; rr ; rr = rrn) {
			rrn = rr->next;
			if (rr->fd>=0) {
				tcpClose(rr->fd);
			}
			if (rr->rBuff!=NULL) {
				free(rr->rBuff);
			}
			pthread_cond_destroy(&(rr->cond));
			free(rr);
		}
		s_RdInodeMap[i] = NULL;
	}
}

static int read_data_refresh_connection(STReadRec *rrec)
{
	if (rrec->fd>=0) {
		csdb_readdec(rrec->ip,rrec->port);
		tcpClose(rrec->fd);
		rrec->fd = -1;
	}

    const uint8_t *pcsData;
    uint32_t csdatasize;
	uint8_t status = fs_readchunk(rrec->inode,rrec->indx,&(rrec->fleng),&(rrec->chunkid),&(rrec->version),&pcsData,&csdatasize);
	if (status!=0) {
		syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32" - fs_readchunk returns status: %s",rrec->inode,rrec->indx,rrec->chunkid,rrec->version,mfsstrerr(status));
		if (status==ERROR_ENOENT) {
			return EBADF;	// stale handle
		}
		return EIO;
	}

    if (rrec->chunkid==0 && pcsData==NULL && csdatasize==0) {
		return 0;
	}
	if (pcsData==NULL || csdatasize==0) {
		syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32" - there are no valid copies",rrec->inode,rrec->indx,rrec->chunkid,rrec->version);
		return ENXIO;
	}

    uint32_t ip = 0, tmpip = 0;
    uint16_t port = 0, tmpport = 0;
    uint32_t cnt = 0, bestcnt = 0xFFFFFFFF;

	// choose chunk server
	while (csdatasize>=6 && bestcnt>0) {
		tmpip = get32bit(&pcsData);
		tmpport = get16bit(&pcsData);
		csdatasize-=6;
		cnt = csdb_getopcnt(tmpip,tmpport);
		if (cnt<bestcnt) {
			ip = tmpip;
			port = tmpport;
			bestcnt = cnt;
		}
	}

    if (ip==0 || port==0) {	// this always should be false
		syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32" - there are no valid copies",rrec->inode,rrec->indx,rrec->chunkid,rrec->version);
		return ENXIO;
	}

	rrec->ip = ip;
	rrec->port = port;

    uint32_t srcip = fs_getsrcip();
	cnt=0;
	while (cnt<10) {
		rrec->fd = tcpSocket();
		if (rrec->fd<0) {
			syslog(LOG_WARNING,"can't create tcp socket: %s",strerr(errno));
			break;
		}

		if (srcip) {
			if (tcpNumBind(rrec->fd,srcip,0)<0) {
				syslog(LOG_WARNING,"can't bind to given ip: %s",strerr(errno));
				tcpClose(rrec->fd);
				rrec->fd=-1;
				break;
			}
		}

		if (tcpNumToConnect(rrec->fd,ip,port,(cnt%2)?(300*(1<<(cnt>>1))):(200*(1<<(cnt>>1))))<0) {
			cnt++;
			if (cnt>=10) {
				syslog(LOG_WARNING,"can't connect to (%08"PRIX32":%"PRIu16"): %s",ip,port,strerr(errno));
			}
			tcpClose(rrec->fd);
			rrec->fd=-1;
		} else {
			cnt=10;
		}
	}

	if (rrec->fd<0) {
		return EIO;
	}

	if (tcpNoDelay(rrec->fd)<0) {
		syslog(LOG_WARNING,"can't set TCP_NODELAY: %s",strerr(errno));
	}

	csdb_readinc(rrec->ip,rrec->port);

	pthread_mutex_lock(&glock);
	rrec->refcnt = 0;
	pthread_mutex_unlock(&glock);

	return 0;
}

void read_inode_ops(uint32_t inode)
{	
// attributes of inode have been changed - force reconnect
	pthread_mutex_lock(&glock);
	for (STReadRec *rrec = s_RdInodeMap[MAPINDX(inode)] ; rrec ; rrec=rrec->mapnext) {
		if (rrec->inode==inode) {
			rrec->noaccesscnt=CLOSEDELAYTICKS;	// if no access then close socket as soon as possible
			rrec->refcnt=REFRESHTICKS;		// force reconnect on forthcoming access
		}
	}
	pthread_mutex_unlock(&glock);
}

int read_data(void *rr, uint64_t offset, uint32_t *size, uint8_t **buff)
{
	STReadRec *rrec = (STReadRec*)rr;

	if (*size==0 || (*size==0 && *buff!=NULL)) {
		return 0;
	}

	pthread_mutex_lock(&glock);
	rrec->waiting++;
	while (rrec->locked) {
		pthread_cond_wait(&(rrec->cond),&glock);
	}
	rrec->waiting--;
	rrec->locked=1;
	uint8_t forceReconnect = (rrec->fd>=0 && rrec->refcnt==REFRESHTICKS)?1:0;
	pthread_mutex_unlock(&glock);

	if (forceReconnect) {
		csdb_readdec(rrec->ip,rrec->port);
		tcpClose(rrec->fd);
		rrec->fd=-1;
	}

	uint8_t eb=1;
	if (*buff==NULL) {	// use internal buffer
		eb=0;
		if (*size>rrec->rBuffSize) {
			if (rrec->rBuff!=NULL) {
				free(rrec->rBuff);
			}

			rrec->rBuffSize = *size;
			rrec->rBuff = (uint8_t*)malloc(rrec->rBuffSize);
			if (rrec->rBuff==NULL) {
				rrec->rBuffSize = 0;
				syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32" - out of memory",rrec->inode,rrec->indx);
				return ENOMEM;	// out of memory
			}
		}
	}

	int err = EIO;
	uint8_t cnt = 0;
    uint8_t *buffPtr = *buff==NULL ? rrec->rBuff : *buff;
	uint64_t currOff = offset;
    uint32_t indx, uiCurSize = *size;
    uint32_t chunkOffSet, chunkSize;

	while (uiCurSize>0) 
    {
		indx = (currOff>>MFSCHUNKBITS);
		if (rrec->fd<0 || rrec->indx != indx) 
        {
			rrec->indx = indx;

			while (cnt < s_MaxRetries) {
				cnt++;
				err = read_data_refresh_connection(rrec);
				if (err==0) {
					break;
				}

				syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32" - can't connect to proper chunkserver (try counter: %"PRIu32")",rrec->inode,rrec->indx,cnt);
				if (err==EBADF) {	// no such inode - it's unrecoverable error
					if (eb) {
						pthread_mutex_lock(&glock);
						if (rrec->waiting) {
							pthread_cond_signal(&(rrec->cond));
						}
						rrec->locked = 0;
						pthread_mutex_unlock(&glock);
					}
					return err;
				}

				if (err==ENXIO) {	// chunk not available - unrecoverable, but wait longer, and make less retries
					sleep(60);
					cnt+=6;
				} else {
					sleep(1+((cnt<30)?(cnt/3):10));
				}
			}//end while

			if (cnt >= s_MaxRetries) {
				if (eb) {
					pthread_mutex_lock(&glock);
					if (rrec->waiting) {
						pthread_cond_signal(&(rrec->cond));
					}
					rrec->locked=0;
					pthread_mutex_unlock(&glock);
				}
				return err;
			}
		}//end if

		if (currOff>=rrec->fleng) {
			break;
		}
		if (currOff+uiCurSize>rrec->fleng) {
			uiCurSize = rrec->fleng-currOff;
		}

		chunkOffSet = (currOff&MFSCHUNKMASK);
		if (chunkOffSet+uiCurSize>MFSCHUNKSIZE) {
			chunkSize = MFSCHUNKSIZE-chunkOffSet;
		} else {
			chunkSize = uiCurSize;
		}

		if (rrec->chunkid>0) 
        {
#if 1
            syslog(LOG_INFO, "begin cache -- %"PRIu64" version:%"PRIu32"--%"PRIu32"--%"PRIu32, rrec->chunkid,rrec->version,chunkOffSet,chunkSize);
           
            if(rrec->indx == 0 && rrec->fleng < 2 * 1024 * 1024)
            {                
                if (file_cache_search(rrec->chunkid,rrec->version,chunkOffSet,chunkSize,buffPtr) == 0)
                {
                    syslog(LOG_INFO, "cache hit -- %"PRIu64" version:%"PRIu32, rrec->chunkid,rrec->version);
                    currOff+=chunkSize;
                    uiCurSize-=chunkSize;
                    buffPtr+=chunkSize;
                }
                else
                {
                    syslog(LOG_WARNING, "cache nohit -- %"PRIu64" version:%"PRIu32, rrec->chunkid,rrec->version);

                    uint8_t *pTmpBuf = (uint8_t *)malloc(rrec->fleng);
                    if (cs_readblock(rrec->fd,rrec->chunkid,rrec->version,0,rrec->fleng, pTmpBuf)<0)
                    {
                        syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32", cs: %08"PRIX32":%"PRIu16" - readblock error (try counter: %"PRIu32")",rrec->inode,rrec->indx,rrec->chunkid,rrec->version,rrec->ip,rrec->port,cnt);
                        csdb_readdec(rrec->ip,rrec->port);
                        tcpClose(rrec->fd);
                        rrec->fd = -1;
                        sleep(1+((cnt<30)?(cnt/3):10));

                        free(pTmpBuf);
                    } else {
                        file_cache_insert(rrec->chunkid,rrec->version,pTmpBuf,rrec->fleng);
                        memcpy(buffPtr, pTmpBuf, chunkSize);
                        currOff+=chunkSize;
                        uiCurSize-=chunkSize;
                        buffPtr+=chunkSize;
                    }
                }//end if              
            }
            else
            {
#endif
                if (cs_readblock(rrec->fd,rrec->chunkid,rrec->version,chunkOffSet,chunkSize,buffPtr)<0)
                {
                    syslog(LOG_WARNING,"file: %"PRIu32", index: %"PRIu32", chunk: %"PRIu64", version: %"PRIu32", cs: %08"PRIX32":%"PRIu16" - readblock error (try counter: %"PRIu32")",rrec->inode,rrec->indx,rrec->chunkid,rrec->version,rrec->ip,rrec->port,cnt);
                    csdb_readdec(rrec->ip,rrec->port);
                    tcpClose(rrec->fd);
                    rrec->fd = -1;
                    sleep(1+((cnt<30)?(cnt/3):10));
                } else {
                    currOff+=chunkSize;
                    uiCurSize-=chunkSize;
                    buffPtr+=chunkSize;
                }
#if 1
            }
#endif
		} else {
			memset(buffPtr,0,chunkSize);
			currOff+=chunkSize;
			uiCurSize-=chunkSize;
			buffPtr+=chunkSize;
		}
	}//end while

	if (rrec->fleng<=offset) {
		*size = 0;
	} else if (rrec->fleng<(offset+(*size))) {
		if (*buff==NULL) {
			*buff = rrec->rBuff;
		}
		*size = rrec->fleng - offset;
	} else {
		if (*buff==NULL) {
			*buff = rrec->rBuff;
		}
	}

	pthread_mutex_lock(&glock);
	rrec->noaccesscnt=0;
	if (eb) {
		if (rrec->waiting) {
			pthread_cond_signal(&(rrec->cond));
		}
		rrec->locked = 0;
	}
	pthread_mutex_unlock(&glock);

	return 0;
}

void read_data_freebuff(void *rr) {
	STReadRec *rrec = (STReadRec*)rr;
	pthread_mutex_lock(&glock);
	if (rrec->waiting) {
		pthread_cond_signal(&(rrec->cond));
	}
	rrec->locked = 0;
	pthread_mutex_unlock(&glock);
}
