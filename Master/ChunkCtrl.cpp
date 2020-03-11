#include "config.h"

#include <time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/in.h>

#include "cfg.h"
#include "ChunkCtrl.h"
#include "ServerCore.h"
#include "sockets.h"
#include "random.h"
#include "slogger.h"
#include "hashfn.h"
#include "median.h"

#define MaxPacketSize 500000000

static int lsock;
static int32_t lsockpdescpos;

// from config
static char *ListenHost;
static char *ListenPort;

CChunkSvrMgr::CChunkSvrMgr():m_chunk_list(NULL),m_repsrc_free(NULL),m_repdst_free(NULL)
{

}

CChunkSvrMgr::~CChunkSvrMgr()
{

}

CChunkSvrMgr* CChunkSvrMgr::getInstance()
{
    static CChunkSvrMgr s_Instance;
    return &s_Instance;
}

void CChunkSvrMgr::init(void)
{
    uint32_t hash;
    for (hash=0 ; hash<CSDBHASHSIZE ; hash++) {
        m_svr_hash[hash]=NULL;
    }

    for (hash=0 ; hash<REPHASHSIZE ; hash++) {
        m_rep_hash[hash]=NULL;
    }

    m_repsrc_free=NULL;
    m_repdst_free=NULL;
    m_chunk_list = NULL;
}

void CChunkSvrMgr::clear(void)
{
    CChunkConn *eptr,*eaptr;
    packetStruct *pptr,*paptr;

    eptr = m_chunk_list;
    while (eptr) {
        if (eptr->inputpacket.packet) {
            free(eptr->inputpacket.packet);
        }
        pptr = eptr->outputhead;
        while (pptr) {
            if (pptr->packet) {
                free(pptr->packet);
            }
            paptr = pptr;
            pptr = pptr->next;
            free(paptr);
        }
        if (eptr->servstrip) {
            free(eptr->servstrip);
        }
        eaptr = eptr;
        eptr = eptr->next;
        free(eaptr);
    }

    m_chunk_list=NULL;
}

int CChunkSvrMgr::new_connection(uint32_t ip,uint16_t port,CChunkConn *eptr)
{
	ChunkSvrList *csptr;
	uint32_t hash = CSDBHASHFN(ip,port);
	for (csptr = m_svr_hash[hash] ; csptr ; csptr = csptr->next) {
		if (csptr->ip == ip && csptr->port == port) {
			if (csptr->eptr!=NULL) {
				return -1;
			}
			csptr->eptr = eptr;
			return 0;
		}
	}

	csptr = (ChunkSvrList*)malloc(sizeof(ChunkSvrList));
	passert(csptr);
	csptr->ip = ip;
	csptr->port = port;
	csptr->eptr = eptr;

	csptr->next = m_svr_hash[hash];
	m_svr_hash[hash] = csptr;

	return 1;
}

void CChunkSvrMgr::lost_connection(uint32_t ip,uint16_t port)
{
	ChunkSvrList *csptr;
	uint32_t hash = CSDBHASHFN(ip,port);
	for (csptr = m_svr_hash[hash] ; csptr ; csptr = csptr->next) {
		if (csptr->ip == ip && csptr->port == port) {
			csptr->eptr = NULL;
			return;
		}
	}
}

uint32_t CChunkSvrMgr::get_svrlist_size(void)
{
    uint32_t i=0;
	ChunkSvrList *csptr;
	for (uint32_t hash=0 ; hash<CSDBHASHSIZE ; hash++) {
		for (csptr = m_svr_hash[hash] ; csptr ; csptr = csptr->next) {
			i++;
		}
	}

	return i*(4+4+2+8+8+4+8+8+4+4);
}

void CChunkSvrMgr::get_svrlist_data(uint8_t *ptr)
{
	ChunkSvrList *csptr;
	CChunkConn *eptr;

	for (uint32_t hash=0 ; hash<CSDBHASHSIZE ; hash++) {
		for (csptr = m_svr_hash[hash] ; csptr ; csptr = csptr->next) {
			eptr = csptr->eptr;
			if (eptr) {
				put32bit(&ptr,(eptr->version)&0xFFFFFF);
				put32bit(&ptr,eptr->servip);
				put16bit(&ptr,eptr->servport);
				put64bit(&ptr,eptr->usedspace);
				put64bit(&ptr,eptr->totalspace);
				put32bit(&ptr,eptr->chunkscount);
				put64bit(&ptr,eptr->todelUsedSpace);
				put64bit(&ptr,eptr->todelTotalSpace);
				put32bit(&ptr,eptr->todelChunksCount);
				put32bit(&ptr,eptr->errorcounter);
			} else {
				put32bit(&ptr,0x01000000);
				put32bit(&ptr,csptr->ip);
				put16bit(&ptr,csptr->port);
				put64bit(&ptr,0);
				put64bit(&ptr,0);
				put32bit(&ptr,0);
				put64bit(&ptr,0);
				put64bit(&ptr,0);
				put32bit(&ptr,0);
				put32bit(&ptr,0);
			}
		}
	}
}

int CChunkSvrMgr::remove_server(uint32_t ip,uint16_t port) 
{
	ChunkSvrList *csptr,**cspptr;
	uint32_t hash = CSDBHASHFN(ip,port);
	cspptr = m_svr_hash + hash;
	while ((csptr=*cspptr)) {
		if (csptr->ip == ip && csptr->port == port) {
			if (csptr->eptr!=NULL) {
				return -1;
			}
			*cspptr = csptr->next;
			free(csptr);
			return 1;
		} else {
			cspptr = &(csptr->next);
		}
	}
	return 0;
}

//////////////////////////////////////////////////////////////////////////

RepSrcList* CChunkSvrMgr::create_repsrc()
{
	RepSrcList *r;
	if (m_repsrc_free) {
		r = m_repsrc_free;
		m_repsrc_free = r->next;
	} else {
		r = (RepSrcList*)malloc(sizeof(RepSrcList));
		passert(r);
	}

	return r;
}

void CChunkSvrMgr::release_repsrc(RepSrcList *r) 
{
	r->next = m_repsrc_free;
	m_repsrc_free = r;
}

RepDestList* CChunkSvrMgr::create_repdest()
{
	RepDestList *r;
	if (m_repdst_free) {
		r = m_repdst_free;
		m_repdst_free = r->next;
	} else {
		r = (RepDestList*)malloc(sizeof(RepDestList));
		passert(r);
	}
	return r;
}

void CChunkSvrMgr::release_repdest(RepDestList *r)
{
	r->next = m_repdst_free;
	m_repdst_free = r;
}

int CChunkSvrMgr::replication_find(uint64_t chunkid,uint32_t version,void *dst)
{
	uint32_t hash = REPHASHFN(chunkid,version);
	for (RepDestList *r=m_rep_hash[hash] ; r ; r=r->next) {
		if (r->chunkid==chunkid && r->version==version && r->dst==dst) {
			return 1;
		}
	}
	return 0;
}

void CChunkSvrMgr::replication_begin(uint64_t chunkid,uint32_t version,void *dst,uint8_t srccnt,void **src)
{
	uint32_t hash = REPHASHFN(chunkid,version);
	if (srccnt>0) {
		RepDestList *r = create_repdest();
		r->chunkid = chunkid;
		r->version = version;
		r->dst = dst;
		r->srchead = NULL;
		r->next = m_rep_hash[hash];
		m_rep_hash[hash] = r;

		for (uint8_t i=0 ; i<srccnt ; i++) {
			RepSrcList *rs = create_repsrc();
			rs->src = src[i];
			rs->next = r->srchead;
			r->srchead = rs;
			((CChunkConn *)(src[i]))->rrepcounter++;
		}
		((CChunkConn *)(dst))->wrepcounter++;
	}
}

void CChunkSvrMgr::replication_end(uint64_t chunkid,uint32_t version,void *dst) 
{
	uint32_t hash = REPHASHFN(chunkid,version);
	RepDestList *r,**rp;
	RepSrcList *rs,*rsdel;

	rp = &(m_rep_hash[hash]);
	while ((r=*rp)!=NULL) {
		if (r->chunkid==chunkid && r->version==version && r->dst==dst) {
			rs = r->srchead;
			while (rs) {
				rsdel = rs;
				rs = rs->next;
				((CChunkConn *)(rsdel->src))->rrepcounter--;
				release_repsrc(rsdel);
			}

			((CChunkConn *)(dst))->wrepcounter--;
			*rp = r->next;
			release_repdest(r);
		} else {
			rp = &(r->next);
		}
	}
}

void CChunkSvrMgr::replication_disconnected(void *srv)
{
	uint32_t hash;
	RepDestList *r,**rp;
	RepSrcList *rs,*rsdel,**rsp;

	for (hash=0 ; hash<REPHASHSIZE ; hash++) {
		rp = &(m_rep_hash[hash]);
		while ((r=*rp)!=NULL) {
			if (r->dst==srv) {
				rs = r->srchead;
				while (rs) {
					rsdel = rs;
					rs = rs->next;
					((CChunkConn *)(rsdel->src))->rrepcounter--;
					release_repsrc(rsdel);
				}

				((CChunkConn *)(srv))->wrepcounter--;
				*rp = r->next;
				release_repdest(r);

			} else {
				rsp = &(r->srchead);
				while ((rs=*rsp)!=NULL) {
					if (rs->src==srv) {
						((CChunkConn *)(srv))->rrepcounter--;
						*rsp = rs->next;
						release_repsrc(rs);
					} else {
						rsp = &(rs->next);
					}
				}
				rp = &(r->next);
			}
		}
	}
}

//////////////////////////////////////////////////////////////////////////

int matocsserv_space_compare(const void *a,const void *b) {
	const struct servsort {
		double space;
		void *ptr;
	} *aa=(servsort*)a,*bb=(servsort*)b;
	if (aa->space > bb->space) {
		return 1;
	}
	if (aa->space < bb->space) {
		return -1;
	}
	return 0;
}

void CChunkSvrMgr::get_usagedifference(double *minusage,double *maxusage,uint16_t *usablescount,uint16_t *totalscount)
{
	CChunkConn *eptr;
	uint32_t j = 0,k = 0;
	double minspace=1.0,maxspace=0.0;
	double space;

	for (eptr = m_chunk_list ; eptr && j<65535 && k<65535; eptr=eptr->next)
    {
		if (eptr->mode!=KILL) {
			if (eptr->totalspace>0 && eptr->usedspace<=eptr->totalspace) {
				space = (double)(eptr->usedspace) / (double)(eptr->totalspace);
				if (j==0) {
					minspace = maxspace = space;
				} else if (space<minspace) {
					minspace = space;
				} else if (space>maxspace) {
					maxspace = space;
				}
				j++;
			}
			k++;
		}
	}
	if (usablescount) {
		*usablescount = j;
	}
	if (totalscount) {
		*totalscount = k;
	}

	if (j==0) {
		if (minusage) {
			*minusage = 1.0;
		}
		if (maxusage) {
			*maxusage = 0.0;
		}
	} else {
		if (minusage) {
			*minusage = minspace;
		}
		if (maxusage) {
			*maxusage = maxspace;
		}
	}
}

uint16_t CChunkSvrMgr::get_servers_ordered(PtrSvrList ptrs,double maxusagediff,uint32_t *pmin,uint32_t *pmax)
{
	static struct servsort {
		double space;
		void *ptr;
	} servsorttab[MAX_SVR],servtab[MAX_SVR+1];

	CChunkConn *eptr;
	uint32_t i,j,k,min,mid,max;
	double minspace=1.0,maxspace=0.0;
	double space;

//	syslog(LOG_NOTICE,"getservers start");
	j = 0;
    uint64_t tspace = 0,uspace = 0;
	for (eptr = m_chunk_list ; eptr && j<65535; eptr=eptr->next) {
		if (eptr->mode!=KILL && eptr->totalspace>0 && eptr->usedspace<=eptr->totalspace) {
			uspace += eptr->usedspace;
			tspace += eptr->totalspace;
			space = (double)(eptr->usedspace) / (double)(eptr->totalspace);
			if (j==0) {
				minspace = maxspace = space;
			} else if (space<minspace) {
				minspace = space;
			} else if (space>maxspace) {
				maxspace = space;
			}
			servtab[j].ptr = eptr;
			servtab[j].space = space;
//			syslog(LOG_NOTICE,"ptr: %p, space:%lf",eptr,space);
			j++;
		}
	}
	if (j==0) {
//		syslog(LOG_NOTICE,"getservers - noservers");
		return 0;
	}

	space = (double)(uspace)/(double)(tspace);

	min = 0;
	max = j;
	mid = 0;
	for (i=0 ; i<j ; i++) {
		if (servtab[i].space<space-maxusagediff) {
			ptrs[min++]=servtab[i].ptr;
		} else if (servtab[i].space>space+maxusagediff) {
			ptrs[--max]=servtab[i].ptr;
		} else {
			servsorttab[mid++]=servtab[i];
		}
	}

	// random <0-min)
	for (i=0 ; i<min ; i++) {
		// k = random <i,j)
		k = i+rndu32_ranged(min-i);
		// swap(i,k)
		if (i!=k) {
			void* p = ptrs[i];
			ptrs[i] = ptrs[k];
			ptrs[k] = p;
		}
	}

	// random <max-j)
	for (i=max ; i<j ; i++) {
		// k = random <i,j)
		k = i+rndu32_ranged(j-i);
		// swap(i,k)
		if (i!=k) {
			void* p = ptrs[i];
			ptrs[i] = ptrs[k];
			ptrs[k] = p;
		}
	}

	// sort <min-max)
	if (mid>0) {
		qsort(servsorttab,mid,sizeof(struct servsort),matocsserv_space_compare);
	}
	for (i=0 ; i<mid ; i++) {
		ptrs[min+i]=servsorttab[i].ptr;
	}
	if (pmin!=NULL) {
		*pmin=min;
	}
	if (pmax!=NULL) {
		*pmax=j-max;
	}

	return j;
}


int matocsserv_carry_compare(const void *a,const void *b) {
	const struct rservsort {
		double w;
		double carry;
		CChunkConn *ptr;
	} *aa=(rservsort*)a,*bb=(rservsort*)b;
	if (aa->carry > bb->carry) {
		return -1;
	}
	if (aa->carry < bb->carry) {
		return 1;
	}
	return 0;
}

uint16_t CChunkSvrMgr::get_servers_wrandom(PtrSvrList ptrs,double tolerance,uint16_t demand)
{
	static struct rservsort {
		double w;
		double carry;
		CChunkConn *ptr;
	} servtab[MAX_SVR+1];

	CChunkConn *eptr;

	/* find max total space */
	uint64_t maxtotalspace = 0;
	for (eptr = m_chunk_list ; eptr ; eptr=eptr->next)
    {
		if ((eptr->mode==HEADER || eptr->mode==DATA) && eptr->totalspace > maxtotalspace) 
        {
			maxtotalspace = eptr->totalspace;
		}
	}

	if (maxtotalspace==0) {
		return 0;
	}

	/* find median usage */
	uint32_t allcnt=0;
    double servmed[MAX_SVR];
	for (eptr = m_chunk_list ; eptr && allcnt<MAX_SVR ; eptr=eptr->next)
    {
		if (eptr->mode!=KILL && eptr->totalspace>0 
            && eptr->usedspace<=eptr->totalspace 
            && (eptr->totalspace - eptr->usedspace)>MFSCHUNKSIZE)
        {
			servmed[allcnt] = (double)(eptr->usedspace)/(double)(eptr->totalspace);
			allcnt++;
		}
	}

    double median,m;
	uint8_t useonlymedian = 0;
	if (allcnt>=5) {
		median = median_find(servmed,allcnt);
		uint32_t mediancnt = 0;

		for (eptr = m_chunk_list ; eptr && allcnt<MAX_SVR ; eptr=eptr->next)
        {
			if (eptr->mode!=KILL && eptr->totalspace>0 
                && eptr->usedspace<=eptr->totalspace 
                && (eptr->totalspace - eptr->usedspace)>MFSCHUNKSIZE)
            {
				m = (double)(eptr->usedspace)/(double)(eptr->totalspace);
				if (m > median - tolerance && m < median + tolerance) {
					mediancnt++;
				}
			}
		}

		if (mediancnt * 3 > allcnt * 2) {
			useonlymedian = 1;
		}
	} else {
		median = 0.0; // make compiler happy
	}

	allcnt=0;
	uint32_t availcnt=0;
	for (eptr = m_chunk_list ; eptr && allcnt<MAX_SVR ; eptr=eptr->next) 
    {
		if (eptr->mode!=KILL && eptr->totalspace>0 
            && eptr->usedspace<=eptr->totalspace 
            && (eptr->totalspace - eptr->usedspace)>MFSCHUNKSIZE)
        {
			m = (double)(eptr->usedspace)/(double)(eptr->totalspace);
			if (useonlymedian==0 || (m > median - tolerance && m < median + tolerance)) {
				servtab[allcnt].w = (double)eptr->totalspace/(double)maxtotalspace;
				servtab[allcnt].carry = eptr->carry;
				servtab[allcnt].ptr = eptr;
				allcnt++;
				if (eptr->carry>=1.0) {
					availcnt++;
				}
			}
		}
	}

	if (demand>allcnt) {
		demand=allcnt;
	}

    double carry;
    uint32_t i;
	while (availcnt<demand) {
		availcnt=0;
		for (i=0 ; i<allcnt ; i++) {
			carry = servtab[i].carry + servtab[i].w;
			if (carry>10.0) {
				carry = 10.0;
			}
			servtab[i].carry = carry;
			servtab[i].ptr->carry = carry;
			if (carry>=1.0) {
				availcnt++;
			}
		}
	}

	qsort(servtab,allcnt,sizeof(struct rservsort),matocsserv_carry_compare);
	for (i=0 ; i<demand ; i++) {
		ptrs[i] = servtab[i].ptr;
		servtab[i].ptr->carry-=1.0;
	}

	return demand;
}

uint16_t CChunkSvrMgr::get_servers_lessrepl(PtrSvrList ptrs,uint16_t replimit)
{
	uint32_t j=0,k,r;
	for (CChunkConn *eptr = m_chunk_list ; eptr && j<MAX_SVR; eptr=eptr->next) {
		if (eptr->mode!=KILL && eptr->totalspace>0 
            && eptr->usedspace<=eptr->totalspace 
            && (eptr->totalspace - eptr->usedspace)>(eptr->totalspace/100) 
            && eptr->wrepcounter<replimit) {
			ptrs[j] = (void*)eptr;
			j++;
		}
	}
	if (j==0) {
		return 0;
	}

    void *x;
	for (k=0 ; k<j-1 ; k++) {
		r = k + rndu32_ranged(j-k);
		if (r!=k) {
			x = ptrs[k];
			ptrs[k] = ptrs[r];
			ptrs[r] = x;
		}
	}

	return j;
}

void CChunkSvrMgr::get_allspace(uint64_t *totalspace,uint64_t *availspace)
{
	uint64_t tspace = 0,uspace = 0;
	for (CChunkConn *eptr = m_chunk_list ; eptr ; eptr=eptr->next) {
		if (eptr->mode!=KILL && eptr->totalspace>0) {
			tspace += eptr->totalspace;
			uspace += eptr->usedspace;
		}
	}

	*totalspace = tspace;
	*availspace = tspace-uspace;
}

//////////////////////////////////////////////////////////////////////////

char* matocsserv_getstrip(void *e) {
	CChunkConn *eptr = (CChunkConn *)e;
	static char *empty=const_cast<char*>("???");
	if (eptr->mode!=KILL && eptr->servstrip) {
		return eptr->servstrip;
	}
	return empty;
}

int matocsserv_getlocation(void *e,uint32_t *servip,uint16_t *servport) {
	CChunkConn *eptr = (CChunkConn *)e;
	if (eptr->mode!=KILL) {
		*servip = eptr->servip;
		*servport = eptr->servport;
		return 0;
	}
	return -1;
}

/* for future use */
int matocsserv_send_chunk_checksum(void *e,uint64_t chunkid,uint32_t version) {
	CChunkConn *eptr = (CChunkConn *)e;
	uint8_t *data;

	if (eptr->mode!=KILL) {
		data = eptr->createPacket(ANTOCS_CHUNK_CHECKSUM,8+4);
		put64bit(&data,chunkid);
		put32bit(&data,version);
	}
	return 0;
}

int matocsserv_send_createchunk(void *e,uint64_t chunkid,uint32_t version) {
	CChunkConn *eptr = (CChunkConn *)e;
	uint8_t *data;

	if (eptr->mode!=KILL) {
		data = eptr->createPacket(MATOCS_CREATE,8+4);
		put64bit(&data,chunkid);
		put32bit(&data,version);
	}
	return 0;
}

int matocsserv_send_deletechunk(void *e,uint64_t chunkid,uint32_t version) {
	CChunkConn *eptr = (CChunkConn *)e;
	uint8_t *data;

	if (eptr->mode!=KILL) {
		data = eptr->createPacket(MATOCS_DELETE,8+4);
		put64bit(&data,chunkid);
		put32bit(&data,version);
		eptr->delcounter++;
	}
	return 0;
}

int matocsserv_send_replicatechunk(void *e,uint64_t chunkid,uint32_t version,void *src) {
	CChunkConn *eptr = (CChunkConn *)e;
	CChunkConn *srceptr = (CChunkConn *)src;
	uint8_t *data;

	if (CChunkSvrMgr::getInstance()->replication_find(chunkid,version,eptr)) {
		return -1;
	}

	if (eptr->mode!=KILL && srceptr->mode!=KILL) {
		data = eptr->createPacket(MATOCS_REPLICATE,8+4+4+2);
		put64bit(&data,chunkid);
		put32bit(&data,version);
		put32bit(&data,srceptr->servip);
		put16bit(&data,srceptr->servport);
		CChunkSvrMgr::getInstance()->replication_begin(chunkid,version,eptr,1,&src);
		eptr->carry = 0;
	}

	return 0;
}

int matocsserv_send_replicatechunk_xor(void *e,uint64_t chunkid,uint32_t version,uint8_t cnt,void **src,uint64_t *srcchunkid,uint32_t *srcversion) {
	CChunkConn *eptr = (CChunkConn *)e;
	CChunkConn *srceptr;
	uint8_t i;

	if (CChunkSvrMgr::getInstance()->replication_find(chunkid,version,eptr)) {
		return -1;
	}

	if (eptr->mode!=KILL) {
		for (i=0 ; i<cnt ; i++) {
			srceptr = (CChunkConn *)(src[i]);
			if (srceptr->mode==KILL) {
				return 0;
			}
		}

		uint8_t *data = eptr->createPacket(MATOCS_REPLICATE,8+4+cnt*(8+4+4+2));
		put64bit(&data,chunkid);
		put32bit(&data,version);
		for (i=0 ; i<cnt ; i++) {
			srceptr = (CChunkConn *)(src[i]);
			put64bit(&data,srcchunkid[i]);
			put32bit(&data,srcversion[i]);
			put32bit(&data,srceptr->servip);
			put16bit(&data,srceptr->servport);
		}

		CChunkSvrMgr::getInstance()->replication_begin(chunkid,version,eptr,cnt,src);
		eptr->carry = 0;
	}

	return 0;
}

int matocsserv_send_setchunkversion(void *e,uint64_t chunkid,uint32_t version,uint32_t oldversion) {
	CChunkConn *eptr = (CChunkConn *)e;
	uint8_t *data;

	if (eptr->mode!=KILL) {
		data = eptr->createPacket(MATOCS_SET_VERSION,8+4+4);
		put64bit(&data,chunkid);
		put32bit(&data,version);
		put32bit(&data,oldversion);
	}
	return 0;
}

int matocsserv_send_duplicatechunk(void *e,uint64_t chunkid,uint32_t version,uint64_t oldchunkid,uint32_t oldversion) {
	CChunkConn *eptr = (CChunkConn *)e;
	uint8_t *data;

	if (eptr->mode!=KILL) {
		data = eptr->createPacket(MATOCS_DUPLICATE,8+4+8+4);
		put64bit(&data,chunkid);
		put32bit(&data,version);
		put64bit(&data,oldchunkid);
		put32bit(&data,oldversion);
	}
	return 0;
}

int matocsserv_send_truncatechunk(void *e,uint64_t chunkid,uint32_t length,uint32_t version,uint32_t oldversion) {
	CChunkConn *eptr = (CChunkConn *)e;
	uint8_t *data;

	if (eptr->mode!=KILL) {
		data = eptr->createPacket(MATOCS_TRUNCATE,8+4+4+4);
		put64bit(&data,chunkid);
		put32bit(&data,length);
		put32bit(&data,version);
		put32bit(&data,oldversion);
	}

	return 0;
}

int matocsserv_send_duptruncchunk(void *e,uint64_t chunkid,uint32_t version,uint64_t oldchunkid,uint32_t oldversion,uint32_t length) {
	CChunkConn *eptr = (CChunkConn *)e;
	uint8_t *data;

	if (eptr->mode!=KILL) {
		data = eptr->createPacket(MATOCS_DUPTRUNC,8+4+8+4+4);
		put64bit(&data,chunkid);
		put32bit(&data,version);
		put64bit(&data,oldchunkid);
		put32bit(&data,oldversion);
		put32bit(&data,length);
	}
	return 0;
}

int matocsserv_send_chunkop(void *e,uint64_t chunkid,uint32_t version,uint32_t newversion,
                            uint64_t copychunkid,uint32_t copyversion,uint32_t leng)
{
	CChunkConn *eptr = (CChunkConn *)e;
	uint8_t *data;

	if (eptr->mode!=KILL) {
		data = eptr->createPacket(MATOCS_CHUNKOP,8+4+4+8+4+4);
		put64bit(&data,chunkid);
		put32bit(&data,version);
		put32bit(&data,newversion);
		put64bit(&data,copychunkid);
		put32bit(&data,copyversion);
		put32bit(&data,leng);
	}

	return 0;
}

void matocsserv_gotpacket(CChunkConn *eptr,uint32_t type,const uint8_t *data,uint32_t length) {
	switch (type) {
		case ANTOAN_NOP:
			break;
		case ANTOAN_UNKNOWN_COMMAND: // for future use
			break;
		case ANTOAN_BAD_COMMAND_SIZE: // for future use
			break;
		case CSTOMA_REGISTER:
			eptr->svr_register(data,length);
			break;
		case CSTOMA_SPACE:
			eptr->svr_space(data,length);
			break;
		case CSTOMA_CHUNK_DAMAGED:
			eptr->handle_chunk_damaged(data,length);
			break;
		case CSTOMA_CHUNK_LOST:
			eptr->chunks_lost(data,length);
			break;
		case CSTOMA_CHUNK_NEW:
			eptr->chunks_new(data,length);
			break;
		case CSTOMA_ERROR_OCCURRED:
			eptr->error_occurred(data,length);
			break;
		case CSTOAN_CHUNK_CHECKSUM:
			eptr->got_chunk_checksum(data,length);
			break;
		case CSTOMA_CREATE:
			eptr->got_createchunk_status(data,length);
			break;
		case CSTOMA_DELETE:
			eptr->got_deletechunk_status(data,length);
			break;
		case CSTOMA_REPLICATE:
			eptr->got_replicatechunk_status(data,length);
			break;
		case CSTOMA_DUPLICATE:
			eptr->got_duplicatechunk_status(data,length);
			break;
		case CSTOMA_SET_VERSION:
			eptr->got_setchunkversion_status(data,length);
			break;
		case CSTOMA_TRUNCATE:
			eptr->got_truncatechunk_status(data,length);
			break;
		case CSTOMA_DUPTRUNC:
			eptr->got_duptruncchunk_status(data,length);
			break;
		default:
			syslog(LOG_NOTICE,"master <-> chunkservers module: got unknown message (type:%"PRIu32")",type);
			eptr->mode=KILL;
	}
}

void matocsserv_term(void) {
	syslog(LOG_INFO,"master <-> chunkservers module: closing %s:%s",ListenHost,ListenPort);
	tcpClose(lsock);
    
    CChunkSvrMgr::getInstance()->clear();

	free(ListenHost);
	free(ListenPort);
}

void matocsserv_read(CChunkConn *eptr) {
	int32_t i;
	uint32_t type,size;
	const uint8_t *ptr;
	for (;;) {
		i=read(eptr->sock,eptr->inputpacket.startptr,eptr->inputpacket.bytesleft);
		if (i==0) {
			syslog(LOG_NOTICE,"connection with CS(%s) has been closed by peer",eptr->servstrip);
			eptr->mode = KILL;
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_arg_errlog_silent(LOG_NOTICE,"read from CS(%s) error",eptr->servstrip);
				eptr->mode = KILL;
			}
			return;
		}
		eptr->inputpacket.startptr+=i;
		eptr->inputpacket.bytesleft-=i;

		if (eptr->inputpacket.bytesleft>0) {
			return;
		}

		if (eptr->mode==HEADER) {
			ptr = eptr->hdrbuff+4;
			size = get32bit(&ptr);

			if (size>0) {
				if (size>MaxPacketSize) {
					syslog(LOG_WARNING,"CS(%s) packet too long (%"PRIu32"/%u)",eptr->servstrip,size,MaxPacketSize);
					eptr->mode = KILL;
					return;
				}
				eptr->inputpacket.packet = (uint8_t*)malloc(size);
				passert(eptr->inputpacket.packet);
				eptr->inputpacket.bytesleft = size;
				eptr->inputpacket.startptr = eptr->inputpacket.packet;
				eptr->mode = DATA;
				continue;
			}
			eptr->mode = DATA;
		}

		if (eptr->mode==DATA) {
			ptr = eptr->hdrbuff;
			type = get32bit(&ptr);
			size = get32bit(&ptr);

			eptr->mode=HEADER;
			eptr->inputpacket.bytesleft = 8;
			eptr->inputpacket.startptr = eptr->hdrbuff;

			matocsserv_gotpacket(eptr,type,eptr->inputpacket.packet,size);

			if (eptr->inputpacket.packet) {
				free(eptr->inputpacket.packet);
			}
			eptr->inputpacket.packet=NULL;
		}
	}
}

void matocsserv_write(CChunkConn *eptr) {
	int32_t i;
	packetStruct *pack;
	for (;;) {
		pack = eptr->outputhead;
		if (pack==NULL) {
			return;
		}
		i=write(eptr->sock,pack->startptr,pack->bytesleft);
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_arg_errlog_silent(LOG_NOTICE,"write to CS(%s) error",eptr->servstrip);
				eptr->mode = KILL;
			}
			return;
		}
		pack->startptr+=i;
		pack->bytesleft-=i;
		if (pack->bytesleft>0) {
			return;
		}
		free(pack->packet);
		eptr->outputhead = pack->next;
		if (eptr->outputhead==NULL) {
			eptr->outputtail = &(eptr->outputhead);
		}
		free(pack);
	}
}

void matocsserv_desc(struct pollfd *pdesc,uint32_t *ndesc) {
	uint32_t pos = *ndesc;
	CChunkConn *eptr;
	pdesc[pos].fd = lsock;
	pdesc[pos].events = POLLIN;
	lsockpdescpos = pos;
	pos++;
	for (eptr=CChunkSvrMgr::getInstance()->m_chunk_list ; eptr ; eptr=eptr->next) {
		if (eptr->mode!=KILL) {
			pdesc[pos].fd = eptr->sock;
			pdesc[pos].events = POLLIN;
			eptr->pdescpos = pos;
			if (eptr->outputhead!=NULL) {
				pdesc[pos].events |= POLLOUT;
			}
			pos++;
		} else {
			eptr->pdescpos = -1;
		}
	}
	*ndesc = pos;
}

void matocsserv_serve(struct pollfd *pdesc) {
	uint32_t now=CServerCore::get_time();
	uint32_t peerip;
	CChunkConn *eptr,**kptr;
	int ns;
	static uint64_t lastaction = 0;
	static uint64_t lastdisconnect = 0;
	uint64_t unow;
	uint32_t timeoutadd;

	if (lastaction==0) {
		lastaction = CServerCore::get_precise_utime();
	}

	if (lsockpdescpos>=0 && (pdesc[lsockpdescpos].revents & POLLIN)) {
		ns=tcpAccept(lsock);
		if (ns<0) {
			mfs_errlog_silent(LOG_NOTICE,"Master<->CS socket: accept error");
		} else {
			tcpNonBlock(ns);
			tcpNoDelay(ns);
			eptr = (CChunkConn*)malloc(sizeof(CChunkConn));
			passert(eptr);
			eptr->next = CChunkSvrMgr::getInstance()->m_chunk_list;
			CChunkSvrMgr::getInstance()->m_chunk_list = eptr;
            eptr->init(ns, now);

			eptr->mode = HEADER;
			tcpGetPeer(eptr->sock,&peerip,NULL);
			eptr->servstrip = CConnEntry::makestrip(peerip);
			eptr->version = 0;
			eptr->servip = 0;
			eptr->servport = 0;
			eptr->timeout = 60;
			eptr->usedspace = eptr->totalspace = eptr->chunkscount = 0;
			eptr->todelUsedSpace = eptr->todelTotalSpace = eptr->todelChunksCount = 0;
			eptr->errorcounter = eptr->rrepcounter = eptr->wrepcounter = eptr->delcounter = 0;
			eptr->incsdb = 0;

			eptr->carry=(double)(rndu32())/(double)(0xFFFFFFFFU);
		}
	}

// read
	for (eptr=CChunkSvrMgr::getInstance()->m_chunk_list ; eptr ; eptr=eptr->next) {
		if (eptr->pdescpos>=0) {
			if (pdesc[eptr->pdescpos].revents & (POLLERR|POLLHUP)) {
				eptr->mode = KILL;
			}
			if ((pdesc[eptr->pdescpos].revents & POLLIN) && eptr->mode!=KILL) {
				eptr->lastread = now;
				matocsserv_read(eptr);
			}
		}
	}

// timeout fix
	unow = CServerCore::get_precise_utime();
	timeoutadd = (unow-lastaction)/1000000;
	if (timeoutadd) { // more than one second passed - then fix 'timeout' timestamps
		for (eptr=CChunkSvrMgr::getInstance()->m_chunk_list ; eptr ; eptr=eptr->next) {
			eptr->lastread += timeoutadd;
		}
	}
	lastaction = unow;

// write
	for (eptr=CChunkSvrMgr::getInstance()->m_chunk_list ; eptr ; eptr=eptr->next) {

		if ((uint32_t)(eptr->lastwrite+(eptr->timeout/3))<(uint32_t)now && eptr->outputhead==NULL && eptr->mode!=KILL) {
			eptr->createPacket(ANTOAN_NOP,0);
		}
		if (eptr->pdescpos>=0) {
			if ((((pdesc[eptr->pdescpos].events & POLLOUT)==0 && (eptr->outputhead))
                || (pdesc[eptr->pdescpos].revents & POLLOUT)) && eptr->mode!=KILL) {
				eptr->lastwrite = now;
				matocsserv_write(eptr);
			}
		}
		if ((uint32_t)(eptr->lastread+eptr->timeout)<(uint32_t)now) {
			eptr->mode = KILL;
		}
	}

// close
	kptr = &CChunkSvrMgr::getInstance()->m_chunk_list;
	while ((eptr=*kptr)) {
		if (eptr->mode == KILL && (lastdisconnect+100000 < CServerCore::get_precise_utime())) {
			double us,ts;
			us = (double)(eptr->usedspace)/(double)(1024*1024*1024);
			ts = (double)(eptr->totalspace)/(double)(1024*1024*1024);
			syslog(LOG_NOTICE,"chunkserver disconnected - ip: %s, port: %"PRIu16", usedspace: %"PRIu64" (%.2lf GiB), totalspace: %"PRIu64" (%.2lf GiB)",eptr->servstrip,eptr->servport,eptr->usedspace,us,eptr->totalspace,ts);
			
            CChunkSvrMgr::getInstance()->replication_disconnected(eptr);
			ChkMgr->chunk_server_disconnected(eptr);

			if (eptr->incsdb) {
				CChunkSvrMgr::getInstance()->lost_connection(eptr->servip,eptr->servport);
			}
			tcpClose(eptr->sock);
            eptr->clear();

            if (eptr->servstrip) {
				free(eptr->servstrip);
			}
			*kptr = eptr->next;
			free(eptr);
			lastdisconnect = CServerCore::get_precise_utime();
		} else {
			kptr = &(eptr->next);
		}
	}
}

void matocsserv_reload(void) {
	char *oldListenHost,*oldListenPort;
	int newlsock;

	oldListenHost = ListenHost;
	oldListenPort = ListenPort;
	ListenHost = cfg_getstr("MATOCS_LISTEN_HOST","*");
	ListenPort = cfg_getstr("MATOCS_LISTEN_PORT","9420");
	if (strcmp(oldListenHost,ListenHost)==0 && strcmp(oldListenPort,ListenPort)==0) {
		free(oldListenHost);
		free(oldListenPort);
		mfs_arg_syslog(LOG_NOTICE,"master <-> chunkservers module: socket address hasn't changed (%s:%s)",ListenHost,ListenPort);
		return;
	}

	newlsock = tcpSocket();
	if (newlsock<0) {
		mfs_errlog(LOG_WARNING,"master <-> chunkservers module: socket address has changed, but can't create new socket");
		free(ListenHost);
		free(ListenPort);
		ListenHost = oldListenHost;
		ListenPort = oldListenPort;
		return;
	}

	tcpNonBlock(newlsock);
	tcpNoDelay(newlsock);
	tcpReuseAddr(newlsock);
	if (tcpSetAcceptFilter(newlsock)<0 && errno!=ENOTSUP) {
		mfs_errlog_silent(LOG_NOTICE,"master <-> chunkservers module: can't set accept filter");
	}

	if (tcpStrListen(newlsock,ListenHost,ListenPort,100)<0) {
		mfs_arg_errlog(LOG_ERR,"master <-> chunkservers module: socket address has changed, but can't listen on socket (%s:%s)",ListenHost,ListenPort);
		free(ListenHost);
		free(ListenPort);
		ListenHost = oldListenHost;
		ListenPort = oldListenPort;
		tcpClose(newlsock);
		return;
	}

	mfs_arg_syslog(LOG_NOTICE,"master <-> chunkservers module: socket address has changed, now listen on %s:%s",ListenHost,ListenPort);
	free(oldListenHost);
	free(oldListenPort);
	tcpClose(lsock);
	lsock = newlsock;
}

int matocsserv_init(void) {
	ListenHost = cfg_getstr("MATOCS_LISTEN_HOST","*");
	ListenPort = cfg_getstr("MATOCS_LISTEN_PORT","9420");

	lsock = tcpSocket();
	if (lsock<0) {
		mfs_errlog(LOG_ERR,"master <-> chunkservers module: can't create socket");
		return -1;
	}
	tcpNonBlock(lsock);
	tcpNoDelay(lsock);
	tcpReuseAddr(lsock);
	if (tcpSetAcceptFilter(lsock)<0 && errno!=ENOTSUP) {
		mfs_errlog_silent(LOG_NOTICE,"master <-> chunkservers module: can't set accept filter");
	}
	if (tcpStrListen(lsock,ListenHost,ListenPort,100)<0) {
		mfs_arg_errlog(LOG_ERR,"master <-> chunkservers module: can't listen on %s:%s",ListenHost,ListenPort);
		return -1;
	}
	mfs_arg_syslog(LOG_NOTICE,"master <-> chunkservers module: listen on %s:%s",ListenHost,ListenPort);

	CChunkSvrMgr::getInstance()->init();

    CServerCore::getInstance()->reload_register(matocsserv_reload);
	CServerCore::getInstance()->destruct_register(matocsserv_term);
    CServerCore::getInstance()->poll_register(matocsserv_desc,matocsserv_serve);

    return 0;
}
