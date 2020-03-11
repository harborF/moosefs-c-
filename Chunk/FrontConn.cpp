#include "config.h"

#define BGJOBSCNT 1000

#include <time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <syslog.h>
#include <netinet/in.h>

#include "DataPack.h"
#include "FrontConn.h"
#include "cfg.h"
#include "ServerCore.h"
#include "sockets.h"
#include "HddSpaceMgr.h"
#include "charts.h"
#ifdef BGJOBS
#include "BgJobsMgr.h"
#endif

// connection timeout in seconds
#define CSSERV_TIMEOUT 5

#define CONNECT_RETRIES 10
#define CONNECT_TIMEOUT(cnt) (((cnt)%2)?(300000*(1<<((cnt)>>1))):(200000*(1<<((cnt)>>1))))

#define MaxPacketSize 100000

//CFrontConn.state
enum {
    IDLE_STATE,
    READ_STATE,
    WRITELAST_STATE,
    CONNECTING_STATE,
    WRITEINIT_STATE,
    WRITEFWD_STATE,
    WRITEFINISH_STATE,
    CLOSE_STATE,
    CLOSEWAIT_STATE,
    CLOSED_STATE
};

static int lsock;
static CFrontConn *s_pCsServHead=NULL;
static int32_t lSockPdescPos;

#ifdef BGJOBS
static void *jpool;
static int jobfd;
static int32_t jobFdPdescPos;
#endif

static uint32_t mylistenip;
static uint16_t mylistenport;

static uint64_t stats_bytesin=0;
static uint64_t stats_bytesout=0;
static uint32_t stats_hlopr=0;
static uint32_t stats_hlopw=0;
static uint32_t stats_maxjobscnt=0;

// from config
static char *ListenHost;
static char *ListenPort;

void csserv_stats(uint64_t *bin,uint64_t *bout,uint32_t *hlopr,uint32_t *hlopw,uint32_t *maxjobscnt) {
	*bin = stats_bytesin;
	*bout = stats_bytesout;
	*hlopr = stats_hlopr;
	*hlopw = stats_hlopw;
	*maxjobscnt = stats_maxjobscnt;
	stats_bytesin = 0;
	stats_bytesout = 0;
	stats_hlopr = 0;
	stats_hlopw = 0;
	stats_maxjobscnt = 0;
}

void* csserv_preserve_inputpacket(CFrontConn *eptr) {
	void* ret;
	ret = eptr->inputpacket.packet;
	eptr->inputpacket.packet = NULL;
	return ret;
}

void csserv_delete_preserved(void *p) {
	if (p) {
		free(p);
	}
}

// initialize connection to another CS
int csserv_initconnect(CFrontConn *eptr) 
{
	eptr->stWEntry.sock=tcpSocket();
	if (eptr->stWEntry.sock<0) {
		mfs_errlog(LOG_WARNING,"create socket, error");
		return -1;
	}
	if (tcpNonBlock(eptr->stWEntry.sock)<0) {
		mfs_errlog(LOG_WARNING,"set nonblock, error");
		tcpClose(eptr->stWEntry.sock);
		eptr->stWEntry.sock=-1;
		return -1;
	}

	int status = tcpNumConnect(eptr->stWEntry.sock,eptr->fwdip,eptr->fwdport);
	if (status<0) {
		mfs_errlog(LOG_WARNING,"connect failed, error");
		tcpClose(eptr->stWEntry.sock);
		eptr->stWEntry.sock=-1;
		return -1;
	}

	if (status==0) { // connected immediately
		tcpNoDelay(eptr->stWEntry.sock);
		eptr->state=WRITEINIT_STATE;
	} else {
		eptr->state=CONNECTING_STATE;
		eptr->connstart=CServerCore::get_utime();
	}

	return 0;
}

void csserv_retryconnect(CFrontConn *eptr)
{
	uint8_t *ptr;
	tcpClose(eptr->stWEntry.sock);
	eptr->stWEntry.sock=-1;
	eptr->connretrycnt++;
	if (eptr->connretrycnt<CONNECT_RETRIES) {
		if (csserv_initconnect(eptr)<0) {
			ptr = eptr->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
			put64bit(&ptr,eptr->chunkid);
			put32bit(&ptr,0);
			put8bit(&ptr,ERROR_CANTCONNECT);
			eptr->state = WRITEFINISH_STATE;
			return;
		}
	} else {
		ptr = eptr->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
		put64bit(&ptr,eptr->chunkid);
		put32bit(&ptr,0);
		put8bit(&ptr,ERROR_CANTCONNECT);
		eptr->state = WRITEFINISH_STATE;
		return;
	}
}

int csserv_makefwdpacket(CFrontConn *eptr,const uint8_t *data,uint32_t length)
{
	uint32_t psize = 12+length;
	eptr->fwdbytesleft = 8+psize;
	eptr->fwdinitpacket = (uint8_t*)malloc(eptr->fwdbytesleft);
	passert(eptr->fwdinitpacket);
	eptr->fwdstartptr = eptr->fwdinitpacket;
	if (eptr->fwdinitpacket==NULL) {
		return -1;
	}

	uint8_t *ptr = eptr->fwdinitpacket;
	put32bit(&ptr,CLTOCS_WRITE);
	put32bit(&ptr,psize);
	put64bit(&ptr,eptr->chunkid);
	put32bit(&ptr,eptr->version);
	if (length>0) {
		memcpy(ptr,data,length);
	}

	return 0;
}

#ifdef BGJOBS

void csserv_check_nextpacket(CFrontConn *eptr);

// common - delayed close
void csserv_delayed_close(uint8_t status,void *e) {
	CFrontConn *eptr = (CFrontConn*)e;
	if (eptr->wjobid>0 && eptr->wjobwriteid==0 && status==STATUS_OK) {	// this was job_open
		eptr->chunkisopen = 1;
	}
	if (eptr->chunkisopen) {
		job_close(jpool,NULL,NULL,eptr->chunkid);
		eptr->chunkisopen=0;
	}
	eptr->state = CLOSED_STATE;
}

// bg reading
void csserv_read_continue(CFrontConn *eptr);

void csserv_read_finished(uint8_t status,void *e)
{
	CFrontConn *eptr = (CFrontConn*)e;
	eptr->rjobid=0;
	if (status==STATUS_OK) {
		eptr->todocnt--;
		if (eptr->todocnt==0) {
			csserv_read_continue(eptr);
		}
	} else {
		if (eptr->rpacket) {
			CConnEntry::deletePacket(eptr->rpacket);
			eptr->rpacket = NULL;
		}

		uint8_t *ptr = eptr->createPacket(CSTOCL_READ_STATUS,8+1);
		put64bit(&ptr,eptr->chunkid);
		put8bit(&ptr,status);
		job_close(jpool,NULL,NULL,eptr->chunkid);
		eptr->chunkisopen = 0;
		eptr->state = IDLE_STATE;
	}
}

void csserv_send_finished(CFrontConn *eptr) {
	eptr->todocnt--;
	if (eptr->todocnt==0) {
		csserv_read_continue(eptr);
	}
}

void csserv_read_continue(CFrontConn *eptr)
{
	uint32_t size;
	uint8_t *ptr;

	if (eptr->rpacket) {
		eptr->attachPacket(eptr->rpacket);
		eptr->rpacket=NULL;
		eptr->todocnt++;
	}

	if (eptr->size==0) {	// everything have been read
		ptr = eptr->createPacket(CSTOCL_READ_STATUS,8+1);
		put64bit(&ptr,eptr->chunkid);
		put8bit(&ptr,STATUS_OK);
		job_close(jpool,NULL,NULL,eptr->chunkid);
		eptr->chunkisopen = 0;
		eptr->state = IDLE_STATE;	// no error - do not disconnect - go direct to the IDLE state, ready for requests on the same connection
	} else {
		uint16_t blocknum = (eptr->offset)>>MFSBLOCKBITS;
		uint16_t blockoffset = (eptr->offset)&MFSBLOCKMASK;

		if (((eptr->offset+eptr->size-1)>>MFSBLOCKBITS) == blocknum) {	// last block
			size = eptr->size;
		} else {
			size = MFSBLOCKSIZE-blockoffset;
		}

		eptr->rpacket = CConnEntry::newPacket(CSTOCL_READ_DATA,8+2+2+4+4+size);
		ptr = CConnEntry::getPacketData(eptr->rpacket);
		put64bit(&ptr,eptr->chunkid);
		put16bit(&ptr,blocknum);
		put16bit(&ptr,blockoffset);
		put32bit(&ptr,size);

		eptr->rjobid = job_read(jpool,csserv_read_finished,eptr,eptr->chunkid,eptr->version,blocknum,ptr+4,blockoffset,size,ptr);
		if (eptr->rjobid==0) {
			eptr->state = CLOSE_STATE;
			return;
		}
		eptr->todocnt++;
		eptr->offset+=size;
		eptr->size-=size;
	}
}

void CFrontConn::read_init(const uint8_t *data,uint32_t length)
{
	if (length!=8+4+4+4) {
		syslog(LOG_NOTICE,"CLTOCS_READ - wrong size (%"PRIu32"/20)",length);
		this->state = CLOSE_STATE;
		return;
	}

	uint8_t *ptr;
	this->chunkid = get64bit(&data);
	this->version = get32bit(&data);
	this->offset = get32bit(&data);
	this->size = get32bit(&data);
	uint8_t status = hdd_check_version(this->chunkid,this->version);

	if (status!=STATUS_OK) {
		ptr = this->createPacket(CSTOCL_READ_STATUS,8+1);
		put64bit(&ptr,this->chunkid);
		put8bit(&ptr,status);
		return;
	}
	if (this->size==0) {
		ptr = this->createPacket(CSTOCL_READ_STATUS,8+1);
		put64bit(&ptr,this->chunkid);
		put8bit(&ptr,STATUS_OK);	// no bytes to read - just return STATUS_OK
		return;
	}
	if (this->size>MFSCHUNKSIZE) {
		ptr = this->createPacket(CSTOCL_READ_STATUS,8+1);
		put64bit(&ptr,this->chunkid);
		put8bit(&ptr,ERROR_WRONGSIZE);
		return;
	}
	if (this->offset>=MFSCHUNKSIZE || this->offset+this->size>MFSCHUNKSIZE) {
		ptr = this->createPacket(CSTOCL_READ_STATUS,8+1);
		put64bit(&ptr,this->chunkid);
		put8bit(&ptr,ERROR_WRONGOFFSET);
		return;
	}

	status = hdd_open(this->chunkid);
	if (status!=STATUS_OK) {
		ptr = this->createPacket(CSTOCL_READ_STATUS,8+1);
		put64bit(&ptr,this->chunkid);
		put8bit(&ptr,status);
		return;
	}

	stats_hlopr++;
	this->chunkisopen = 1;
	this->state = READ_STATE;
	this->todocnt = 0;
	this->rjobid = 0;
	csserv_read_continue(this);
}

// bg writing
void csserv_write_finished(uint8_t status,void *e) 
{
    uint8_t *ptr;
	CFrontConn *eptr = (CFrontConn*)e;

    eptr->wjobid = 0;
	if (status!=STATUS_OK) {
		ptr = eptr->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
		put64bit(&ptr,eptr->chunkid);
		put32bit(&ptr,eptr->wjobwriteid);
		put8bit(&ptr,status);
		eptr->state = WRITEFINISH_STATE;
		return;
	}

	if (eptr->wjobwriteid==0) {
		eptr->chunkisopen = 1;
	}

    writestatus **wpptr,*wptr;
	if (eptr->state==WRITELAST_STATE) {
		ptr = eptr->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
		put64bit(&ptr,eptr->chunkid);
		put32bit(&ptr,eptr->wjobwriteid);
		put8bit(&ptr,STATUS_OK);
	} else {
		wpptr = &(eptr->todolist);
		while ((wptr=*wpptr)) {
			if (wptr->writeid==eptr->wjobwriteid) { // found - it means that it was added by status_receive
				ptr = eptr->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
				put64bit(&ptr,eptr->chunkid);
				put32bit(&ptr,eptr->wjobwriteid);
				put8bit(&ptr,STATUS_OK);
				*wpptr = wptr->next;
				free(wptr);
			} else {
				wpptr = &(wptr->next);
			}
		}
		// not found - so add it
		wptr = (writestatus*)malloc(sizeof(writestatus));
		passert(wptr);
		wptr->writeid = eptr->wjobwriteid;
		wptr->next = eptr->todolist;
		eptr->todolist = wptr;
	}
	csserv_check_nextpacket(eptr);
}

void CFrontConn::write_init(const uint8_t *data,uint32_t length) 
{
	if (length<12 || ((length-12)%6)!=0) {
		syslog(LOG_NOTICE,"CLTOCS_WRITE - wrong size (%"PRIu32"/12+N*6)",length);
		this->state = CLOSE_STATE;
		return;
	}

    uint8_t *ptr;
	this->chunkid = get64bit(&data);
	this->version = get32bit(&data);
	uint8_t status = hdd_check_version(this->chunkid,this->version);
	if (status!=STATUS_OK) {
		ptr = this->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
		put64bit(&ptr,this->chunkid);
		put32bit(&ptr,0);
		put8bit(&ptr,status);
		this->state = WRITEFINISH_STATE;
		return;
	}

	if (length>(8+4)) {	// connect to another cs
		this->fwdip = get32bit(&data);
		this->fwdport = get16bit(&data);
		this->connretrycnt = 0;
		if (csserv_makefwdpacket(this,data,length-12-6)<0) {
			ptr = this->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
			put64bit(&ptr,this->chunkid);
			put32bit(&ptr,0);
			put8bit(&ptr,ERROR_CANTCONNECT);
			this->state = WRITEFINISH_STATE;
			return;
		}

		if (csserv_initconnect(this)<0) {
			ptr = this->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
			put64bit(&ptr,this->chunkid);
			put32bit(&ptr,0);
			put8bit(&ptr,ERROR_CANTCONNECT);
			this->state = WRITEFINISH_STATE;
			return;
		}
	} else {
		this->state = WRITELAST_STATE;
	}
	stats_hlopw++;

	this->wjobwriteid = 0;
	this->wjobid = job_open(jpool,csserv_write_finished,this,this->chunkid);
}

void CFrontConn::write_data(const uint8_t *data,uint32_t length)
{
	if (length<8+4+2+2+4+4) {
		syslog(LOG_NOTICE,"CLTOCS_WRITE_DATA - wrong size (%"PRIu32"/24+size)",length);
		this->state = CLOSE_STATE;
		return;
	}

	uint8_t *ptr;
	uint64_t chunkid = get64bit(&data);
	uint32_t writeid = get32bit(&data);
	uint16_t blocknum = get16bit(&data);
	uint16_t offset = get16bit(&data);
	uint32_t size = get32bit(&data);

	if (length!=8+4+2+2+4+4+size) {
		syslog(LOG_NOTICE,"CLTOCS_WRITE_DATA - wrong size (%"PRIu32"/24+%"PRIu32")",length,size);
		this->state = CLOSE_STATE;
		return;
	}

	if (chunkid!=this->chunkid) {
		ptr = this->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
		put64bit(&ptr,chunkid);
		put32bit(&ptr,writeid);
		put8bit(&ptr,ERROR_WRONGCHUNKID);
		this->state = WRITEFINISH_STATE;
		return;
	}

	if (this->wpacket) {
		csserv_delete_preserved(this->wpacket);
	}

	this->wpacket = csserv_preserve_inputpacket(this);
	this->wjobwriteid = writeid;
	this->wjobid = job_write(jpool,csserv_write_finished,this,chunkid,this->version,blocknum,data+4,offset,size,data);
}

void CFrontConn::write_status(const uint8_t *data,uint32_t length)
{
	if (length!=8+4+1) {
		syslog(LOG_NOTICE,"CSTOCL_WRITE_STATUS - wrong size (%"PRIu32"/13)",length);
		this->state = CLOSE_STATE;
		return;
	}

	uint64_t chunkid = get64bit(&data);
	uint32_t writeid = get32bit(&data);
	uint8_t status = get8bit(&data);

	uint8_t *ptr;
	writestatus **wpptr,*wptr;
	if (this->chunkid!=chunkid) {
		ptr = this->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
		put64bit(&ptr,this->chunkid);
		put32bit(&ptr,0);
		put8bit(&ptr,ERROR_WRONGCHUNKID);
		this->state = WRITEFINISH_STATE;
		return;
	}

	if (status!=STATUS_OK) {
		ptr = this->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
		put64bit(&ptr,this->chunkid);
		put32bit(&ptr,writeid);
		put8bit(&ptr,status);
		this->state = WRITEFINISH_STATE;
		return;
	}

	wpptr = &(this->todolist);
	while ((wptr=*wpptr)) {
		if (wptr->writeid==writeid) { // found - means it was added by write_finished
			ptr = this->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
			put64bit(&ptr,chunkid);
			put32bit(&ptr,writeid);
			put8bit(&ptr,STATUS_OK);
			*wpptr = wptr->next;
			free(wptr);
			return;
		} else {
			wpptr = &(wptr->next);
		}
	}
	// if not found then add record
	wptr = (writestatus*)malloc(sizeof(writestatus));
	passert(wptr);
	wptr->writeid = writeid;
	wptr->next = this->todolist;
	this->todolist = wptr;
}

void csserv_fwderror(CFrontConn *eptr) 
{
	uint8_t *ptr = eptr->createPacket(CSTOCL_WRITE_STATUS,8+4+1);
	put64bit(&ptr,eptr->chunkid);
	put32bit(&ptr,0);
	if (eptr->state==CONNECTING_STATE) {
		put8bit(&ptr,ERROR_CANTCONNECT);
	} else {
		put8bit(&ptr,ERROR_DISCONNECTED);
	}
	eptr->state = WRITEFINISH_STATE;
}

#endif

/* IDLE operations */
void CFrontConn::get_chunk_blocks(const uint8_t *data,uint32_t length)
{
	if (length!=8+4) {
		syslog(LOG_NOTICE,"CSTOCS_GET_CHUNK_BLOCKS - wrong size (%"PRIu32"/12)",length);
		this->state = CLOSE_STATE;
		return;
	}

    uint16_t blocks;
	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
	uint8_t status = hdd_get_blocks(chunkid,version,&blocks);

	uint8_t *ptr = this->createPacket(CSTOCS_GET_CHUNK_BLOCKS_STATUS,8+4+2+1);
	put64bit(&ptr,chunkid);
	put32bit(&ptr,version);
	put16bit(&ptr,blocks);
	put8bit(&ptr,status);
}

void CFrontConn::chunk_checksum(const uint8_t *data,uint32_t length) 
{
	if (length!=8+4) {
		syslog(LOG_NOTICE,"ANTOCS_CHUNK_CHECKSUM - wrong size (%"PRIu32"/12)",length);
		this->state = CLOSE_STATE;
		return;
	}

	uint8_t *ptr;
	uint32_t checksum;
	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
	uint8_t status = hdd_get_checksum(chunkid,version,&checksum);
	if (status!=STATUS_OK) {
		ptr = this->createPacket(CSTOAN_CHUNK_CHECKSUM,8+4+1);
	} else {
		ptr = this->createPacket(CSTOAN_CHUNK_CHECKSUM,8+4+4);
	}

	put64bit(&ptr,chunkid);
	put32bit(&ptr,version);
	if (status!=STATUS_OK) {
		put8bit(&ptr,status);
	} else {
		put32bit(&ptr,checksum);
	}
}

void CFrontConn::chunk_checksum_tab(const uint8_t *data,uint32_t length) 
{
	if (length!=8+4) {
		syslog(LOG_NOTICE,"ANTOCS_CHUNK_CHECKSUM_TAB - wrong size (%"PRIu32"/12)",length);
		this->state = CLOSE_STATE;
		return;
	}

    uint8_t *ptr;
    uint8_t crctab[4096];
	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
	uint8_t status = hdd_get_checksum_tab(chunkid,version,crctab);
	if (status!=STATUS_OK) {
		ptr = this->createPacket(CSTOAN_CHUNK_CHECKSUM_TAB,8+4+1);
	} else {
		ptr = this->createPacket(CSTOAN_CHUNK_CHECKSUM_TAB,8+4+4096);
	}

	put64bit(&ptr,chunkid);
	put32bit(&ptr,version);
	if (status!=STATUS_OK) {
		put8bit(&ptr,status);
	} else {
		memcpy(ptr,crctab,4096);
	}
}

void CFrontConn::hdd_list_v1(const uint8_t *data,uint32_t length)
{
	(void)data;
	if (length!=0) {
		syslog(LOG_NOTICE,"CLTOCS_HDD_LIST(1) - wrong size (%"PRIu32"/0)",length);
		this->state = CLOSE_STATE;
		return;
	}

	uint32_t l = hdd_diskinfo_v1_size();	// lock
	uint8_t *ptr = this->createPacket(CSTOCL_HDD_LIST_V1,l);
	hdd_diskinfo_v1_data(ptr);	// unlock
}

void CFrontConn::hdd_list_v2(const uint8_t *data,uint32_t length)
{
    (void)data;
	if (length!=0) {
		syslog(LOG_NOTICE,"CLTOCS_HDD_LIST(2) - wrong size (%"PRIu32"/0)",length);
		this->state = CLOSE_STATE;
		return;
	}
	uint32_t l = hdd_diskinfo_v2_size();	// lock
	uint8_t *ptr = this->createPacket(CSTOCL_HDD_LIST_V2,l);
	hdd_diskinfo_v2_data(ptr);	// unlock
}

void CFrontConn::svr_chart(const uint8_t *data,uint32_t length)
{
	if (length!=4) {
		syslog(LOG_NOTICE,"CLTOAN_CHART - wrong size (%"PRIu32"/4)",length);
		this->state = CLOSE_STATE;
		return;
	}

	uint32_t chartid = get32bit(&data);
	uint32_t l = charts_make_png(chartid);
	uint8_t *ptr = this->createPacket(ANTOCL_CHART,l);
	if (l>0) {
		charts_get_png(ptr);
	}
}

void CFrontConn::svr_chart_data(const uint8_t *data,uint32_t length) 
{
	if (length!=4) {
		syslog(LOG_NOTICE,"CLTOAN_CHART_DATA - wrong size (%"PRIu32"/4)",length);
		this->state = CLOSE_STATE;
		return;
	}

	uint32_t chartid = get32bit(&data);
	uint32_t l = charts_datasize(chartid);
	uint8_t *ptr = this->createPacket(ANTOCL_CHART_DATA,l);
	if (l>0) {
		charts_makedata(ptr,chartid);
	}
}


void csserv_outputcheck(CFrontConn *eptr) {
	if (eptr->state==READ_STATE) {
#ifdef BGJOBS
		csserv_send_finished(eptr);
#else /* BGJOBS */
		csserv_read_continue(eptr);
#endif
	}
}

void csserv_close(CFrontConn *eptr) {
#ifdef BGJOBS
	if (eptr->rjobid>0) {
		job_pool_disable_job(jpool,eptr->rjobid);
		job_pool_change_callback(jpool,eptr->rjobid,csserv_delayed_close,eptr);
		eptr->state = CLOSEWAIT_STATE;
	} else if (eptr->wjobid>0) {
		job_pool_disable_job(jpool,eptr->wjobid);
		job_pool_change_callback(jpool,eptr->wjobid,csserv_delayed_close,eptr);
		eptr->state = CLOSEWAIT_STATE;
	} else {
		if (eptr->chunkisopen) {
			job_close(jpool,NULL,NULL,eptr->chunkid);
			eptr->chunkisopen=0;
		}
		eptr->state = CLOSED_STATE;
	}
#else /* BGJOBS */
	if (eptr->chunkisopen) {
		hdd_close(eptr->chunkid);
		eptr->chunkisopen=0;
	}
	eptr->state = CLOSED_STATE;
#endif /* BGJOBS */
}

void csserv_gotpacket(CFrontConn *eptr,uint32_t type,const uint8_t *data,uint32_t length)
{
//	syslog(LOG_NOTICE,"packet %u:%u",type,length);
	if (type==ANTOAN_NOP) {
		return;
	}
	if (type==ANTOAN_UNKNOWN_COMMAND) { // for future use
		return;
	}
	if (type==ANTOAN_BAD_COMMAND_SIZE) { // for future use
		return;
	}
	if (eptr->state==IDLE_STATE) {
		switch (type) {
		case CLTOCS_READ:
			eptr->read_init(data,length);
			break;
		case CLTOCS_WRITE:
			eptr->write_init(data,length);
			break;
		case CSTOCS_GET_CHUNK_BLOCKS:
			eptr->get_chunk_blocks(data,length);
			break;
		case ANTOCS_CHUNK_CHECKSUM:
			eptr->chunk_checksum(data,length);
			break;
		case ANTOCS_CHUNK_CHECKSUM_TAB:
			eptr->chunk_checksum_tab(data,length);
			break;
		case CLTOCS_HDD_LIST_V1:
			eptr->hdd_list_v1(data,length);
			break;
		case CLTOCS_HDD_LIST_V2:
			eptr->hdd_list_v2(data,length);
			break;
		case CLTOAN_CHART:
			eptr->svr_chart(data,length);
			break;
		case CLTOAN_CHART_DATA:
			eptr->svr_chart_data(data,length);
			break;
		default:
			syslog(LOG_NOTICE,"got unknown message (type:%"PRIu32")",type);
			eptr->state = CLOSE_STATE;
		}
	} else if (eptr->state==WRITELAST_STATE) {
		if (type==CLTOCS_WRITE_DATA) {
			eptr->write_data(data,length);
		} else {
			syslog(LOG_NOTICE,"got unknown message (type:%"PRIu32")",type);
			eptr->state = CLOSE_STATE;
		}
	} else if (eptr->state==WRITEFWD_STATE) {
		switch (type) {
		case CLTOCS_WRITE_DATA:
			eptr->write_data(data,length);
			break;
		case CSTOCL_WRITE_STATUS:
			eptr->write_status(data,length);
			break;
		default:
			syslog(LOG_NOTICE,"got unknown message (type:%"PRIu32")",type);
			eptr->state = CLOSE_STATE;
		}
	} else if (eptr->state==WRITEFINISH_STATE) {
		if (type==CLTOCS_WRITE_DATA) {
			return;
		} else {
			syslog(LOG_NOTICE,"got unknown message (type:%"PRIu32")",type);
			eptr->state = CLOSE_STATE;
		}
	} else {
		syslog(LOG_NOTICE,"got unknown message (type:%"PRIu32")",type);
		eptr->state = CLOSE_STATE;
	}
}

void csserv_term(void) {
	CFrontConn *eptr,*eaptr;
	packetStruct *pptr,*paptr;
#ifdef BGJOBS
	writestatus *wptr,*waptr;
#endif

	syslog(LOG_NOTICE,"closing %s:%s",ListenHost,ListenPort);
	tcpClose(lsock);

#ifdef BGJOBS
	job_pool_delete(jpool);
#endif

	eptr = s_pCsServHead;
	while (eptr) {
		if (eptr->chunkisopen) {
			hdd_close(eptr->chunkid);
		}
		tcpClose(eptr->sock);
		if (eptr->stWEntry.sock>=0) {
			tcpClose(eptr->stWEntry.sock);
		}
		if (eptr->inputpacket.packet) {
			free(eptr->inputpacket.packet);
		}
		if (eptr->stWEntry.inputpacket.packet) {
			free(eptr->stWEntry.inputpacket.packet);
		}
		if (eptr->fwdinitpacket) {
			free(eptr->fwdinitpacket);
		}
#ifdef BGJOBS
		wptr = eptr->todolist;
		while (wptr) {
			waptr = wptr;
			wptr = wptr->next;
			free(waptr);
		}
#endif
		pptr = eptr->outputhead;
		while (pptr) {
			if (pptr->packet) {
				free(pptr->packet);
			}
			paptr = pptr;
			pptr = pptr->next;
			free(paptr);
		}
		eaptr = eptr;
		eptr = eptr->next;
		free(eaptr);
	}
	s_pCsServHead=NULL;
	free(ListenHost);
	free(ListenPort);
}

void csserv_check_nextpacket(CFrontConn *eptr) {
	uint32_t type,size;
	const uint8_t *ptr;
	if (eptr->state==WRITEFWD_STATE) {
		if (eptr->mode==DATA && eptr->inputpacket.bytesleft==0 && eptr->fwdbytesleft==0) {
			ptr = eptr->hdrbuff;
			type = get32bit(&ptr);
			size = get32bit(&ptr);

			eptr->mode = HEADER;
			eptr->inputpacket.bytesleft = 8;
			eptr->inputpacket.startptr = eptr->hdrbuff;

			csserv_gotpacket(eptr,type,eptr->inputpacket.packet+8,size);

			if (eptr->inputpacket.packet) {
				free(eptr->inputpacket.packet);
			}
			eptr->inputpacket.packet=NULL;
		}
	} else {
		if (eptr->mode==DATA && eptr->inputpacket.bytesleft==0) {
			ptr = eptr->hdrbuff;
			type = get32bit(&ptr);
			size = get32bit(&ptr);

			eptr->mode = HEADER;
			eptr->inputpacket.bytesleft = 8;
			eptr->inputpacket.startptr = eptr->hdrbuff;

			csserv_gotpacket(eptr,type,eptr->inputpacket.packet,size);

			if (eptr->inputpacket.packet) {
				free(eptr->inputpacket.packet);
			}
			eptr->inputpacket.packet=NULL;
		}
	}
}

void csserv_fwdconnected(CFrontConn *eptr) {
	int status;
	status = tcpGetStatus(eptr->stWEntry.sock);
	if (status) {
		mfs_errlog_silent(LOG_WARNING,"connection failed, error");
		csserv_fwderror(eptr);
		return;
	}
	tcpNoDelay(eptr->stWEntry.sock);
	eptr->state=WRITEINIT_STATE;
}

void csserv_fwdread(CFrontConn *eptr) {
	int32_t i;
	uint32_t type,size;
	const uint8_t *ptr;
    CConnEntry* pConn = &eptr->stWEntry;
    packetStruct *pack = &pConn->inputpacket;

	if (eptr->fwdmode==HEADER) {
		i=read(pConn->sock, pack->startptr, pack->bytesleft);
		if (i==0) {
			csserv_fwderror(eptr);
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"(fwdread) read error");
				csserv_fwderror(eptr);
			}
			return;
		}
		stats_bytesin+=i;
		pack->startptr+=i;
		pack->bytesleft-=i;
		if (pack->bytesleft>0) {
			return;
		}
		ptr = pConn->hdrbuff+4;
		size = get32bit(&ptr);
		if (size>MaxPacketSize) {
			syslog(LOG_WARNING,"(fwdread) packet too long (%"PRIu32"/%u)",size,MaxPacketSize);
			csserv_fwderror(eptr);
			return;
		}

		if (size>0) {
			pack->packet = (uint8_t*)malloc(size);
			passert(pack->packet);
			pack->startptr = pack->packet;
		}
		pack->bytesleft = size;
		eptr->fwdmode = DATA;
	}

	if (eptr->fwdmode==DATA) {
		if (pack->bytesleft>0) {
			i=read(pConn->sock, pack->startptr, pack->bytesleft);
			if (i==0) {
				csserv_fwderror(eptr);
				return;
			}
			if (i<0) {
				if (errno!=EAGAIN) {
					mfs_errlog_silent(LOG_NOTICE,"(fwdread) read error");
					csserv_fwderror(eptr);
				}
				return;
			}
			stats_bytesin+=i;
			pack->startptr+=i;
			pack->bytesleft-=i;
			if (pack->bytesleft>0) {
				return;
			}
		}

		ptr = pConn->hdrbuff;
		type = get32bit(&ptr);
		size = get32bit(&ptr);

		eptr->fwdmode=HEADER;
		pack->bytesleft = 8;
		pack->startptr = pConn->hdrbuff;

		csserv_gotpacket(eptr,type,pack->packet,size);

		if (pack->packet) {
			free(pack->packet);
		}
		pack->packet=NULL;
	}
}

void csserv_fwdwrite(CFrontConn *eptr) {
	int32_t i;
    CConnEntry* pConn = &eptr->stWEntry;
    packetStruct *pack = &pConn->inputpacket;

	if (eptr->fwdbytesleft>0) {
		i=write(pConn->sock, eptr->fwdstartptr,eptr->fwdbytesleft);
		if (i==0) {
			csserv_fwderror(eptr);
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"(fwdwrite) write error");
				csserv_fwderror(eptr);
			}
			return;
		}
		stats_bytesout+=i;
		eptr->fwdstartptr+=i;
		eptr->fwdbytesleft-=i;
	}

	if (eptr->fwdbytesleft==0) {
		free(eptr->fwdinitpacket);
		eptr->fwdinitpacket = NULL;
		eptr->fwdstartptr = NULL;
		eptr->fwdmode = HEADER;
		pack->bytesleft = 8;
		pack->startptr = pConn->hdrbuff;
		pack->packet = NULL;
		eptr->state = WRITEFWD_STATE;
	}
}

void csserv_forward(CFrontConn *eptr)
{
	int32_t i;
	uint32_t type,size;
	const uint8_t *ptr;
    packetStruct *pack = &eptr->inputpacket;

	if (eptr->mode==HEADER) {
		i=read(eptr->sock, pack->startptr, pack->bytesleft);
		if (i==0) {
			eptr->state = CLOSE_STATE;
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"(forward) read error");
				eptr->state = CLOSE_STATE;
			}
			return;
		}
		stats_bytesin+=i;
		pack->startptr+=i;
		pack->bytesleft-=i;
		if (pack->bytesleft>0) {
			return;
		}
		ptr = eptr->hdrbuff+4;
		size = get32bit(&ptr);
		if (size>MaxPacketSize) {
			syslog(LOG_WARNING,"(forward) packet too long (%"PRIu32"/%u)",size,MaxPacketSize);
			eptr->state = CLOSE_STATE;
			return;
		}
		pack->packet = (uint8_t*)malloc(size+8);
		passert(pack->packet);
		memcpy(pack->packet, eptr->hdrbuff, 8);
		pack->bytesleft = size;
		pack->startptr = pack->packet+8;
		eptr->fwdbytesleft = 8;
		eptr->fwdstartptr = pack->packet;
		eptr->mode = DATA;
	}

	if (pack->bytesleft>0) {
		i=read(eptr->sock, pack->startptr, pack->bytesleft);
		if (i==0) {
			eptr->state = CLOSE_STATE;
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"(forward) read error: %s");
				eptr->state = CLOSE_STATE;
			}
			return;
		}
		stats_bytesin+=i;
		pack->startptr+=i;
		pack->bytesleft-=i;
		eptr->fwdbytesleft+=i;
	}

	if (eptr->fwdbytesleft>0) {
		i=write(eptr->stWEntry.sock,eptr->fwdstartptr,eptr->fwdbytesleft);
		if (i==0) {
			csserv_fwderror(eptr);
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"(forward) write error: %s");
				csserv_fwderror(eptr);
			}
			return;
		}
		stats_bytesout+=i;
		eptr->fwdstartptr+=i;
		eptr->fwdbytesleft-=i;
	}

#ifdef BGJOBS
	if (pack->bytesleft==0 && eptr->fwdbytesleft==0 && eptr->wjobid==0) {
#else
	if (pack->bytesleft==0 && eptr->fwdbytesleft==0) {
#endif
		ptr = eptr->hdrbuff;
		type = get32bit(&ptr);
		size = get32bit(&ptr);

		eptr->mode = HEADER;
		pack->bytesleft = 8;
		pack->startptr = eptr->hdrbuff;

		csserv_gotpacket(eptr,type, pack->packet+8,size);

		if (pack->packet) {
			free(pack->packet);
		}
		pack->packet=NULL;
	}
}

void csserv_read(CFrontConn *eptr) {
	int32_t i;
	uint32_t type,size;
	const uint8_t *ptr;
    packetStruct *pack = &eptr->inputpacket;

	if (eptr->mode == HEADER) {
		i=read(eptr->sock, pack->startptr, pack->bytesleft);
		if (i==0) {
			eptr->state = CLOSE_STATE;
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"(read) read error");
				eptr->state = CLOSE_STATE;
			}
			return;
		}
		stats_bytesin+=i;
		pack->startptr+=i;
		pack->bytesleft-=i;

		if (pack->bytesleft>0) {
			return;
		}

		ptr = eptr->hdrbuff+4;
		size = get32bit(&ptr);

		if (size>0) {
			if (size>MaxPacketSize) {
				syslog(LOG_WARNING,"(read) packet too long (%"PRIu32"/%u)",size,MaxPacketSize);
				eptr->state = CLOSE_STATE;
				return;
			}
			pack->packet = (uint8_t*)malloc(size);
			passert(pack->packet);
			pack->startptr = pack->packet;
		}
		pack->bytesleft = size;
		eptr->mode = DATA;
	}

	if (eptr->mode == DATA) {
		if (pack->bytesleft>0) {
			i=read(eptr->sock, pack->startptr, pack->bytesleft);
			if (i==0) { 
				eptr->state = CLOSE_STATE;
				return;
			}
			if (i<0) {
				if (errno!=EAGAIN) {
					mfs_errlog_silent(LOG_NOTICE,"(read) read error");
					eptr->state = CLOSE_STATE;
				}
				return;
			}
			stats_bytesin+=i;
			pack->startptr+=i;
			pack->bytesleft-=i;

			if (pack->bytesleft>0) {
				return;
			}
		}
#ifdef BGJOBS
		if (eptr->wjobid==0) {
#endif
		ptr = eptr->hdrbuff;
		type = get32bit(&ptr);
		size = get32bit(&ptr);

		eptr->mode = HEADER;
		pack->bytesleft = 8;
		pack->startptr = eptr->hdrbuff;

		csserv_gotpacket(eptr,type,pack->packet,size);

		if (pack->packet) {
			free(pack->packet);
		}
		pack->packet=NULL;
#ifdef BGJOBS
		}
#endif
	}
}

void csserv_write(CFrontConn *eptr) {
	packetStruct *pack;
	int32_t i;

	for (;;) {
		pack = eptr->outputhead;
		if (pack==NULL) {
			return;
		}
		i=write(eptr->sock,pack->startptr,pack->bytesleft);
		if (i==0) {
			eptr->state = CLOSE_STATE;
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"(write) write error");
				eptr->state = CLOSE_STATE;
			}
			return;
		}
		stats_bytesout+=i;
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
		csserv_outputcheck(eptr);
	}
}

void csserv_desc(struct pollfd *pdesc,uint32_t *ndesc)
{
	uint32_t pos = *ndesc;
	CFrontConn *eptr;
	pdesc[pos].fd = lsock;
	pdesc[pos].events = POLLIN;
	lSockPdescPos = pos;
	pos++;
#ifdef BGJOBS
	pdesc[pos].fd = jobfd;
	pdesc[pos].events = POLLIN;
	jobFdPdescPos = pos;
	pos++;
#endif

	for (eptr=s_pCsServHead ; eptr ; eptr=eptr->next) {
		eptr->pdescpos = -1;
		eptr->stWEntry.pdescpos = -1;
		switch (eptr->state) {
			case IDLE_STATE:
			case READ_STATE:
			case WRITELAST_STATE:
				pdesc[pos].fd = eptr->sock;
				pdesc[pos].events = 0;
				eptr->pdescpos = pos;
				if (eptr->inputpacket.bytesleft>0) {
					pdesc[pos].events |= POLLIN;
				}
				if (eptr->outputhead!=NULL) {
					pdesc[pos].events |= POLLOUT;
				}
				pos++;
				break;
			case CONNECTING_STATE:
				pdesc[pos].fd = eptr->stWEntry.sock;
				pdesc[pos].events = POLLOUT;
				eptr->stWEntry.pdescpos = pos;
				pos++;
				break;
			case WRITEINIT_STATE:
				if (eptr->fwdbytesleft>0) {
					pdesc[pos].fd = eptr->stWEntry.sock;
					pdesc[pos].events = POLLOUT;
					eptr->stWEntry.pdescpos = pos;
					pos++;
				}
				break;
			case WRITEFWD_STATE:
				pdesc[pos].fd = eptr->stWEntry.sock;
				pdesc[pos].events = POLLIN;
				eptr->stWEntry.pdescpos = pos;
				if (eptr->fwdbytesleft>0) {
					pdesc[pos].events |= POLLOUT;
				}
				pos++;

				pdesc[pos].fd = eptr->sock;
				pdesc[pos].events = 0;
				eptr->pdescpos = pos;
				if (eptr->inputpacket.bytesleft>0) {
					pdesc[pos].events |= POLLIN;
				}
				if (eptr->outputhead!=NULL) {
					pdesc[pos].events |= POLLOUT;
				}
				pos++;
				break;
			case WRITEFINISH_STATE:
				if (eptr->outputhead!=NULL) {
					pdesc[pos].fd = eptr->sock;
					pdesc[pos].events = POLLOUT;
					eptr->pdescpos = pos;
					pos++;
				}
				break;
		}
	}
	*ndesc = pos;
}

void csserv_serve(struct pollfd *pdesc)
{
	uint32_t now=CServerCore::get_time();
	uint64_t usecnow=CServerCore::get_utime();
	CFrontConn *eptr,**kptr;
	packetStruct *pptr,*paptr;
#ifdef BGJOBS
	writestatus *wptr,*waptr;
	uint32_t jobscnt;
#endif
	int ns;
	uint8_t lstate;

	if (lSockPdescPos>=0 && (pdesc[lSockPdescPos].revents & POLLIN)) {
		ns=tcpAccept(lsock);
		if (ns<0) {
			mfs_errlog_silent(LOG_NOTICE,"accept error");
		} else {
#ifdef BGJOBS
			if (job_pool_jobs_count(jpool)>=(BGJOBSCNT*9)/10) {
				syslog(LOG_WARNING,"jobs queue is full !!!");
				tcpClose(ns);
			} else {
#endif
				tcpNonBlock(ns);
				tcpNoDelay(ns);
				eptr = (CFrontConn*)malloc(sizeof(CFrontConn));
				passert(eptr);
				eptr->next = s_pCsServHead;
				s_pCsServHead = eptr;
				eptr->state = IDLE_STATE;
				eptr->mode = HEADER;
				eptr->fwdmode = HEADER;
				eptr->sock = ns;
				eptr->stWEntry.sock = -1;
				eptr->pdescpos = -1;
				eptr->stWEntry.pdescpos = -1;
				eptr->activity = now;
				eptr->inputpacket.bytesleft = 8;
				eptr->inputpacket.startptr = eptr->hdrbuff;
				eptr->inputpacket.packet = NULL;
				eptr->fwdstartptr = NULL;
				eptr->fwdbytesleft = 0;
				eptr->stWEntry.inputpacket.packet = NULL;
				eptr->fwdinitpacket = NULL;
				eptr->outputhead = NULL;
				eptr->outputtail = &(eptr->outputhead);
				eptr->chunkisopen = 0;
#ifdef BGJOBS
				eptr->wjobid = 0;
				eptr->wjobwriteid = 0;
				eptr->todolist = NULL;

				eptr->rjobid = 0;
				eptr->todocnt = 0;

				eptr->rpacket = NULL;
				eptr->wpacket = NULL;
			}
#endif
		}
	}

#ifdef BGJOBS
	if (jobFdPdescPos>=0 && (pdesc[jobFdPdescPos].revents & POLLIN)) {
		job_pool_check_jobs(jpool);
	}
#endif

	for (eptr=s_pCsServHead ; eptr ; eptr=eptr->next) {
		if (eptr->pdescpos>=0 && (pdesc[eptr->pdescpos].revents & (POLLERR|POLLHUP))) {
			eptr->state = CLOSE_STATE;
		} else if (eptr->stWEntry.pdescpos>=0 && (pdesc[eptr->stWEntry.pdescpos].revents & (POLLERR|POLLHUP))) {
			csserv_fwderror(eptr);
		}
		lstate = eptr->state;
		if (lstate==IDLE_STATE || lstate==READ_STATE || lstate==WRITELAST_STATE || lstate==WRITEFINISH_STATE) {
			if (eptr->pdescpos>=0 && (pdesc[eptr->pdescpos].revents & POLLIN)) {
				eptr->activity = now;
				csserv_read(eptr);
			}
			if (eptr->pdescpos>=0 && (pdesc[eptr->pdescpos].revents & POLLOUT) && eptr->state==lstate) {
				eptr->activity = now;
				csserv_write(eptr);
			}
		} else if (lstate==CONNECTING_STATE && eptr->stWEntry.pdescpos>=0 && (pdesc[eptr->stWEntry.pdescpos].revents & POLLOUT)) { 
			eptr->activity = now;
			csserv_fwdconnected(eptr);
			if (eptr->state==WRITEINIT_STATE) {
				csserv_fwdwrite(eptr); // after connect likely some data can be send
			}
			if (eptr->state==WRITEFWD_STATE) {
				csserv_forward(eptr); // and also some data can be forwarded
			}
		} else if (eptr->state==WRITEINIT_STATE && eptr->stWEntry.pdescpos>=0 && (pdesc[eptr->stWEntry.pdescpos].revents & POLLOUT)) { 
			eptr->activity = now;
			csserv_fwdwrite(eptr); // after sending init packet
			if (eptr->state==WRITEFWD_STATE) {
				csserv_forward(eptr); // likely some data can be forwarded
			}
		} else if (eptr->state==WRITEFWD_STATE) {
			if ((eptr->pdescpos>=0 && (pdesc[eptr->pdescpos].revents & POLLIN)) 
                || (eptr->stWEntry.pdescpos>=0 && (pdesc[eptr->stWEntry.pdescpos].revents & POLLOUT))) {
				eptr->activity = now;
				csserv_forward(eptr);
			}

			if (eptr->stWEntry.pdescpos>=0 && (pdesc[eptr->stWEntry.pdescpos].revents & POLLIN) && eptr->state==lstate) {
				eptr->activity = now;
				csserv_fwdread(eptr);
			}

			if (eptr->pdescpos>=0 && (pdesc[eptr->pdescpos].revents & POLLOUT) && eptr->state==lstate) {
				eptr->activity = now;
				csserv_write(eptr);
			}
		}

		if (eptr->state==WRITEFINISH_STATE && eptr->outputhead==NULL) {
			eptr->state = CLOSE_STATE;
		}

		if (eptr->state==CONNECTING_STATE && eptr->connstart+CONNECT_TIMEOUT(eptr->connretrycnt)<usecnow) {
			csserv_retryconnect(eptr);
		}

		if (eptr->state!=CLOSE_STATE && eptr->state!=CLOSEWAIT_STATE && eptr->state!=CLOSED_STATE && eptr->activity+CSSERV_TIMEOUT<now) {
			eptr->state = CLOSE_STATE;
		}
		if (eptr->state == CLOSE_STATE) {
			csserv_close(eptr);
		}
	}

#ifdef BGJOBS
	jobscnt = job_pool_jobs_count(jpool);
	if (jobscnt>=stats_maxjobscnt) {
		stats_maxjobscnt=jobscnt;
	}
#endif

	kptr = &s_pCsServHead;
	while ((eptr=*kptr)) {
		if (eptr->state == CLOSED_STATE) {
			tcpClose(eptr->sock);
			if (eptr->rpacket) {
				CConnEntry::deletePacket(eptr->rpacket);
			}
			if (eptr->wpacket) {
				csserv_delete_preserved(eptr->wpacket);
			}
			if (eptr->stWEntry.sock>=0) {
				tcpClose(eptr->stWEntry.sock);
			}
			if (eptr->inputpacket.packet) {
				free(eptr->inputpacket.packet);
			}
			if (eptr->stWEntry.inputpacket.packet) {
				free(eptr->stWEntry.inputpacket.packet);
			}
			if (eptr->fwdinitpacket) {
				free(eptr->fwdinitpacket);
			}
#ifdef BGJOBS
			wptr = eptr->todolist;
			while (wptr) {
				waptr = wptr;
				wptr = wptr->next;
				free(waptr);
			}
#endif
			pptr = eptr->outputhead;
			while (pptr) {
				if (pptr->packet) {
					free(pptr->packet);
				}
				paptr = pptr;
				pptr = pptr->next;
				free(paptr);
			}
			*kptr = eptr->next;
			free(eptr);
		} else {
			kptr = &(eptr->next);
		}
	}
}

uint32_t csserv_getlistenip() {
	return mylistenip;
}

uint16_t csserv_getlistenport() {
	return mylistenport;
}

void csserv_reload(void) {
	char *oldListenHost,*oldListenPort;
	int newlsock;

	oldListenHost = ListenHost;
	oldListenPort = ListenPort;
	ListenHost = cfg_getstr("CSSERV_LISTEN_HOST","*");
	ListenPort = cfg_getstr("CSSERV_LISTEN_PORT","9422");
	if (strcmp(oldListenHost,ListenHost)==0 && strcmp(oldListenPort,ListenPort)==0) {
		free(oldListenHost);
		free(oldListenPort);
		mfs_arg_syslog(LOG_NOTICE,"main server module: socket address hasn't changed (%s:%s)",ListenHost,ListenPort);
		return;
	}

	newlsock = tcpSocket();
	if (newlsock<0) {
		mfs_errlog(LOG_WARNING,"main server module: socket address has changed, but can't create new socket");
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
		mfs_errlog_silent(LOG_NOTICE,"main server module: can't set accept filter");
	}
	if (tcpStrListen(newlsock,ListenHost,ListenPort,100)<0) {
		mfs_arg_errlog(LOG_ERR,"main server module: socket address has changed, but can't listen on socket (%s:%s)",ListenHost,ListenPort);
		free(ListenHost);
		free(ListenPort);
		ListenHost = oldListenHost;
		ListenPort = oldListenPort;
		tcpClose(newlsock);
		return;
	}
	mfs_arg_syslog(LOG_NOTICE,"main server module: socket address has changed, now listen on %s:%s",ListenHost,ListenPort);
	free(oldListenHost);
	free(oldListenPort);
	tcpClose(lsock);
	lsock = newlsock;
}

int csserv_init(void) {
	ListenHost = cfg_getstr("CSSERV_LISTEN_HOST","*");
	ListenPort = cfg_getstr("CSSERV_LISTEN_PORT","9422");

	lsock = tcpSocket();
	if (lsock<0) {
		mfs_errlog(LOG_ERR,"main server module: can't create socket");
		return -1;
	}
	tcpNonBlock(lsock);
	tcpNoDelay(lsock);
	tcpReuseAddr(lsock);
	if (tcpSetAcceptFilter(lsock)<0 && errno!=ENOTSUP) {
		mfs_errlog_silent(LOG_NOTICE,"main server module: can't set accept filter");
	}

	tcpResolve(ListenHost,ListenPort,&mylistenip,&mylistenport,1);
	if (tcpNumListen(lsock,mylistenip,mylistenport,100)<0) {
		mfs_errlog(LOG_ERR,"main server module: can't listen on socket");
		return -1;
	}

	mfs_arg_syslog(LOG_NOTICE,"main server module: listen on %s:%s",ListenHost,ListenPort);

	s_pCsServHead = NULL;
	CServerCore::getInstance()->reload_register(csserv_reload);
	CServerCore::getInstance()->destruct_register(csserv_term);
	CServerCore::getInstance()->poll_register(csserv_desc,csserv_serve);

#ifdef BGJOBS
	jpool = job_pool_new(10,BGJOBSCNT,&jobfd);
#endif

	return 0;
}
