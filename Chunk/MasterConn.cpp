#include "config.h"

#include <time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>

#include "cfg.h"
#include "sockets.h"
#include "random.h"
#include "FrontConn.h"
#include "MasterConn.h"
#include "ServerCore.h"
#include "HddSpaceMgr.h"

#define BGJOBS 1
#define BGJOBSCNT 1000

#ifdef BGJOBS
#include "BgJobsMgr.h"
#endif

#define MaxPacketSize 10000

// has to be less than MaxPacketSize on master side divided by 8
#define LOSTCHUNKLIMIT 25000
// has to be less than MaxPacketSize on master side divided by 12
#define NEWCHUNKLIMIT 25000

#ifdef BGJOBS
static void *jpool;
static int jobfd;
static int32_t jobFdPdescPos;
#endif

CMasterConn *CMasterConn::s_Instance = NULL;
// from config
static char *MasterHost;
static char *MasterPort;
static char *BindHost;
static uint32_t Timeout;
static void* reconnect_hook;

static uint64_t stats_bytesout=0;
static uint64_t stats_bytesin=0;
static uint32_t stats_maxjobscnt=0;

void masterconn_stats(uint64_t *bin,uint64_t *bout,uint32_t *maxjobscnt) {
	*bin = stats_bytesin;
	*bout = stats_bytesout;
	*maxjobscnt = stats_maxjobscnt;
	stats_bytesin = 0;
	stats_bytesout = 0;
	stats_maxjobscnt = 0;
}

void masterconn_sendregister(CMasterConn *eptr)
{
	uint32_t myip = csserv_getlistenip();
	uint16_t myport = csserv_getlistenport();
	uint8_t *buff = eptr->createPacket(CSTOMA_REGISTER,1+4+4+2+2);
	put8bit(&buff,50);
	put16bit(&buff,VERSMAJ);
	put8bit(&buff,VERSMID);
	put8bit(&buff,VERSMIN);
	put32bit(&buff,myip);
	put16bit(&buff,myport);
	put16bit(&buff,Timeout);

    uint32_t chunks;
	hdd_get_chunks_begin();
	while ((chunks = hdd_get_chunks_next_list_count())) {
		buff = eptr->createPacket(CSTOMA_REGISTER,1+chunks*(8+4));
		put8bit(&buff,51);
		hdd_get_chunks_next_list_data(buff);
	}
	hdd_get_chunks_end();

	uint64_t usedspace,totalspace;
	uint64_t tdusedspace,tdtotalspace;
	uint32_t chunkcount,tdchunkcount;
	hdd_get_space(&usedspace,&totalspace,&chunkcount,&tdusedspace,&tdtotalspace,&tdchunkcount);

	buff = eptr->createPacket(CSTOMA_REGISTER,1+8+8+4+8+8+4);
	put8bit(&buff,52);
	put64bit(&buff,usedspace);
	put64bit(&buff,totalspace);
	put32bit(&buff,chunkcount);
	put64bit(&buff,tdusedspace);
	put64bit(&buff,tdtotalspace);
	put32bit(&buff,tdchunkcount);
}

void masterconn_check_hdd_reports()
{
	uint8_t *buff;
	CMasterConn *eptr = CMasterConn::s_Instance;
	if (eptr->mode==DATA || eptr->mode==HEADER) {
		if (hdd_spacechanged()) {
			uint64_t usedspace,totalspace,tdusedspace,tdtotalspace;
			uint32_t chunkcount,tdchunkcount;
			buff = eptr->createPacket(CSTOMA_SPACE,8+8+4+8+8+4);
			hdd_get_space(&usedspace,&totalspace,&chunkcount,&tdusedspace,&tdtotalspace,&tdchunkcount);
			put64bit(&buff,usedspace);
			put64bit(&buff,totalspace);
			put32bit(&buff,chunkcount);
			put64bit(&buff,tdusedspace);
			put64bit(&buff,tdtotalspace);
			put32bit(&buff,tdchunkcount);
		}

		uint32_t errorcounter = hdd_errorcounter();
		while (errorcounter) {
			eptr->createPacket(CSTOMA_ERROR_OCCURRED,0);
			errorcounter--;
		}

		uint32_t chunkcounter = hdd_get_damaged_chunk_count();	// lock
		if (chunkcounter) {
			buff = eptr->createPacket(CSTOMA_CHUNK_DAMAGED,8*chunkcounter);
			hdd_get_damaged_chunk_data(buff);	// unlock
		} else {
			hdd_get_damaged_chunk_data(NULL);
		}

		chunkcounter = hdd_get_lost_chunk_count(LOSTCHUNKLIMIT);	// lock
		if (chunkcounter) {
			buff = eptr->createPacket(CSTOMA_CHUNK_LOST,8*chunkcounter);
			hdd_get_lost_chunk_data(buff,LOSTCHUNKLIMIT);	// unlock
		} else {
			hdd_get_lost_chunk_data(NULL,0);
		}

		chunkcounter = hdd_get_new_chunk_count(NEWCHUNKLIMIT);	// lock
		if (chunkcounter) {
			buff = eptr->createPacket(CSTOMA_CHUNK_NEW,12*chunkcounter);
			hdd_get_new_chunk_data(buff,NEWCHUNKLIMIT);	// unlock
		} else {
			hdd_get_new_chunk_data(NULL,0);
		}
	}
}

#ifdef BGJOBS
void masterconn_jobfinished(uint8_t status,void *packet) {
	uint8_t *ptr;
	CMasterConn *eptr = CMasterConn::s_Instance;
	if (eptr->mode==DATA || eptr->mode==HEADER) {
		ptr = CConnEntry::getPacketData(packet);
		ptr[8]=status;
		eptr->attachPacket( packet);
	} else {
		CConnEntry::deletePacket(packet);
	}
}

void masterconn_chunkopfinished(uint8_t status,void *packet) {
	uint8_t *ptr;
	CMasterConn *eptr = CMasterConn::s_Instance;
	if (eptr->mode==DATA || eptr->mode==HEADER) {
		ptr = CConnEntry::getPacketData(packet);
		ptr[32]=status;
		eptr->attachPacket(packet);
	} else {
		CConnEntry::deletePacket(packet);
	}
}

void masterconn_replicationfinished(uint8_t status,void *packet) {
	uint8_t *ptr;
	CMasterConn *eptr = CMasterConn::s_Instance;

    if (eptr->mode==DATA || eptr->mode==HEADER) {
		ptr = CConnEntry::getPacketData(packet);
		ptr[12]=status;
        eptr->attachPacket(packet);
	} else {
		CConnEntry::deletePacket(packet);
	}
}

void masterconn_unwantedjobfinished(uint8_t status,void *packet) {
	(void)status;
	CConnEntry::deletePacket(packet);
}

#endif /* BGJOBS */

void CMasterConn::handle_create(const uint8_t *data,uint32_t length)
{
	if (length!=8+4) {
		syslog(LOG_NOTICE,"MATOCS_CREATE - wrong size (%"PRIu32"/12)",length);
		this->mode = KILL;
		return;
	}

	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
#ifdef BGJOBS
	void *packet = CConnEntry::newPacket(CSTOMA_CREATE,8+1);
	uint8_t *ptr = CConnEntry::getPacketData(packet);
	put64bit(&ptr,chunkid);
	job_create(jpool,masterconn_jobfinished,packet,chunkid,version);
#else /* BGJOBS */
	uint8_t status = hdd_create(chunkid,version);
	ptr = this->createPacket(CSTOMA_CREATE,8+1);
	put64bit(&ptr,chunkid);
	put8bit(&ptr,status);
#endif /* BGJOBS */
}

void CMasterConn::handle_delete(const uint8_t *data,uint32_t length)
{
	if (length!=8+4) {
		syslog(LOG_NOTICE,"MATOCS_DELETE - wrong size (%"PRIu32"/12)",length);
		this->mode = KILL;
		return;
	}

	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
#ifdef BGJOBS
	void *packet = CConnEntry::newPacket(CSTOMA_DELETE,8+1);
	uint8_t *ptr = CConnEntry::getPacketData(packet);
	put64bit(&ptr,chunkid);
	job_delete(jpool,masterconn_jobfinished,packet,chunkid,version);
#else /* BGJOBS */
	uint8_t status = hdd_delete(chunkid,version);
	ptr = this->createPacket(CSTOMA_DELETE,8+1);
	put64bit(&ptr,chunkid);
	put8bit(&ptr,status);
#endif /* BGJOBS */
}

void CMasterConn::handle_setversion(const uint8_t *data,uint32_t length)
{
	if (length!=8+4+4) {
		syslog(LOG_NOTICE,"MATOCS_SET_VERSION - wrong size (%"PRIu32"/16)",length);
		this->mode = KILL;
		return;
	}

	uint64_t chunkid = get64bit(&data);
	uint32_t newversion = get32bit(&data);
	uint32_t version = get32bit(&data);
#ifdef BGJOBS
	void *packet = CConnEntry::newPacket(CSTOMA_SET_VERSION,8+1);
	uint8_t *ptr = CConnEntry::getPacketData(packet);
	put64bit(&ptr,chunkid);
	job_version(jpool,masterconn_jobfinished,packet,chunkid,version,newversion);
#else /* BGJOBS */
	uint8_t status = hdd_version(chunkid,version,newversion);
	ptr = this->createPacket(CSTOMA_SET_VERSION,8+1);
	put64bit(&ptr,chunkid);
	put8bit(&ptr,status);
#endif /* BGJOBS */
}

void CMasterConn::handle_duplicate(const uint8_t *data,uint32_t length)
{
	if (length!=8+4+8+4) {
		syslog(LOG_NOTICE,"MATOCS_DUPLICATE - wrong size (%"PRIu32"/24)",length);
		this->mode = KILL;
		return;
	}

	uint64_t copychunkid = get64bit(&data);
	uint32_t copyversion = get32bit(&data);
	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
#ifdef BGJOBS
	void *packet = CConnEntry::newPacket(CSTOMA_DUPLICATE,8+1);
	uint8_t *ptr = CConnEntry::getPacketData(packet);
	put64bit(&ptr,copychunkid);
	job_duplicate(jpool,masterconn_jobfinished,packet,chunkid,version,version,copychunkid,copyversion);
#else /* BGJOBS */
	uint8_t status = hdd_duplicate(chunkid,version,version,copychunkid,copyversion);
	uint8_t *ptr = this->createPacket(CSTOMA_DUPLICATE,8+1);
	put64bit(&ptr,copychunkid);
	put8bit(&ptr,status);
#endif /* BGJOBS */
}

void CMasterConn::handle_truncate(const uint8_t *data,uint32_t length)
{
	if (length!=8+4+4+4) {
		syslog(LOG_NOTICE,"MATOCS_TRUNCATE - wrong size (%"PRIu32"/20)",length);
		this->mode = KILL;
		return;
	}

	uint64_t chunkid = get64bit(&data);
	uint32_t leng = get32bit(&data);
	uint32_t newversion = get32bit(&data);
	uint32_t version = get32bit(&data);
#ifdef BGJOBS
	void *packet = CConnEntry::newPacket(CSTOMA_TRUNCATE,8+1);
	uint8_t *ptr = CConnEntry::getPacketData(packet);
	put64bit(&ptr,chunkid);
	job_truncate(jpool,masterconn_jobfinished,packet,chunkid,version,newversion,leng);
#else /* BGJOBS */
	uint8_t status = hdd_truncate(chunkid,version,newversion,leng);
	ptr = this->createPacket(CSTOMA_TRUNCATE,8+1);
	put64bit(&ptr,chunkid);
	put8bit(&ptr,status);
#endif /* BGJOBS */
}

void CMasterConn::handle_duptrunc(const uint8_t *data,uint32_t length)
{
	if (length!=8+4+8+4+4) {
		syslog(LOG_NOTICE,"MATOCS_DUPTRUNC - wrong size (%"PRIu32"/28)",length);
		this->mode = KILL;
		return;
	}

	uint64_t copychunkid = get64bit(&data);
	uint32_t copyversion = get32bit(&data);
	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
	uint32_t leng = get32bit(&data);
#ifdef BGJOBS
	void *packet = CConnEntry::newPacket(CSTOMA_DUPTRUNC,8+1);
	uint8_t *ptr = CConnEntry::getPacketData(packet);
	put64bit(&ptr,copychunkid);
	job_duptrunc(jpool,masterconn_jobfinished,packet,chunkid,version,version,copychunkid,copyversion,leng);
#else /* BGJOBS */
	uint8_t status = hdd_duptrunc(chunkid,version,version,copychunkid,copyversion,leng);
	ptr = this->createPacket(CSTOMA_DUPTRUNC,8+1);
	put64bit(&ptr,copychunkid);
	put8bit(&ptr,status);
#endif /* BGJOBS */
}

void CMasterConn::handle_chunkop(const uint8_t *data,uint32_t length)
{
	if (length!=8+4+8+4+4+4) {
		syslog(LOG_NOTICE,"MATOCS_CHUNKOP - wrong size (%"PRIu32"/32)",length);
		this->mode = KILL;
		return;
	}

	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
	uint32_t newversion = get32bit(&data);
	uint64_t copychunkid = get64bit(&data);
	uint32_t copyversion = get32bit(&data);
	uint32_t leng = get32bit(&data);
#ifdef BGJOBS
	void *packet = CConnEntry::newPacket(CSTOMA_CHUNKOP,8+4+4+8+4+4+1);
	uint8_t *ptr = CConnEntry::getPacketData(packet);
	put64bit(&ptr,chunkid);
	put32bit(&ptr,version);
	put32bit(&ptr,newversion);
	put64bit(&ptr,copychunkid);
	put32bit(&ptr,copyversion);
	put32bit(&ptr,leng);
	job_chunkop(jpool,masterconn_chunkopfinished,packet,chunkid,version,newversion,copychunkid,copyversion,leng);
#else /* BGJOBS */
	uint8_t status = hdd_chunkop(chunkid,version,newversion,copychunkid,copyversion,leng);
	ptr = this->createPacket(CSTOMA_CHUNKOP,8+4+4+8+4+4+1);
	put64bit(&ptr,chunkid);
	put32bit(&ptr,version);
	put32bit(&ptr,newversion);
	put64bit(&ptr,copychunkid);
	put32bit(&ptr,copyversion);
	put32bit(&ptr,leng);
	put8bit(&ptr,status);
#endif /* BGJOBS */
}

#ifdef BGJOBS
void CMasterConn::chunk_replicate(const uint8_t *data,uint32_t length)
{
	if (length!=8+4+4+2 && (length<12+18 || length>12+18*100 || (length-12)%18!=0)) {
		syslog(LOG_NOTICE,"MATOCS_REPLICATE - wrong size (%"PRIu32"/18|12+n*18[n:1..100])",length);
		this->mode = KILL;
		return;
	}

    uint32_t ip;
    uint16_t port;
	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
	void *packet = CConnEntry::newPacket(CSTOMA_REPLICATE,8+4+1);
	uint8_t *ptr = CConnEntry::getPacketData(packet);
	put64bit(&ptr,chunkid);
	put32bit(&ptr,version);
	if (length==8+4+4+2) {
		ip = get32bit(&data);
		port = get16bit(&data);
		job_replicate_simple(jpool,masterconn_replicationfinished,packet,chunkid,version,ip,port);
	} else {
		job_replicate(jpool,masterconn_replicationfinished,packet,chunkid,version,(length-12)/18,data);
	}
}

#else /* BGJOBS */

void CMasterConn::chunk_replicate(const uint8_t *data,uint32_t length)
{
	syslog(LOG_WARNING,"This version of chunkserver can perform replication only in background, but was compiled without bgjobs");

	if (length!=8+4+4+2) {
		syslog(LOG_NOTICE,"MATOCS_REPLICATE - wrong size (%"PRIu32"/18)",length);
		this->mode = KILL;
		return;
	}
	uint64_t chunkid = get64bit(&data);
	uint32_t version = get32bit(&data);
	uint8_t *ptr = this->createPacket(CSTOMA_REPLICATE,8+4+1);
	put64bit(&ptr,chunkid);
	put32bit(&ptr,version);
	put8bit(&ptr,ERROR_CANTCONNECT);	// any error
}
#endif

void CMasterConn::chunk_checksum(const uint8_t *data,uint32_t length)
{
	if (length!=8+4) {
		syslog(LOG_NOTICE,"ANTOCS_CHUNK_CHECKSUM - wrong size (%"PRIu32"/12)",length);
		this->mode = KILL;
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

void CMasterConn::chunk_checksum_tab(const uint8_t *data,uint32_t length)
{
	if (length!=8+4) {
		syslog(LOG_NOTICE,"ANTOCS_CHUNK_CHECKSUM_TAB - wrong size (%"PRIu32"/12)",length);
		this->mode = KILL;
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

void masterconn_gotpacket(CMasterConn *eptr,uint32_t type,const uint8_t *data,uint32_t length) {
	switch (type) {
		case ANTOAN_NOP:
			break;
		case ANTOAN_UNKNOWN_COMMAND: // for future use
			break;
		case ANTOAN_BAD_COMMAND_SIZE: // for future use
			break;
		case MATOCS_CREATE:
			eptr->handle_create(data,length);
			break;
		case MATOCS_DELETE:
			eptr->handle_delete(data,length);
			break;
		case MATOCS_SET_VERSION:
			eptr->handle_setversion(data,length);
			break;
		case MATOCS_DUPLICATE:
			eptr->handle_duplicate(data,length);
			break;
		case MATOCS_REPLICATE:
			eptr->chunk_replicate(data,length);
			break;
		case MATOCS_CHUNKOP:
			eptr->handle_chunkop(data,length);
			break;
		case MATOCS_TRUNCATE:
			eptr->handle_truncate(data,length);
			break;
		case MATOCS_DUPTRUNC:
			eptr->handle_duptrunc(data,length);
			break;
		case ANTOCS_CHUNK_CHECKSUM:
			eptr->chunk_checksum(data,length);
			break;
		case ANTOCS_CHUNK_CHECKSUM_TAB:
			eptr->chunk_checksum_tab(data,length);
			break;
		default:
			syslog(LOG_NOTICE,"got unknown message (type:%"PRIu32")",type);
			eptr->mode = KILL;
	}
}


void masterconn_term(void) {
	packetStruct *pptr,*paptr;
	CMasterConn *eptr = CMasterConn::s_Instance;

	job_pool_delete(jpool);

	if (eptr->mode!=FREE && eptr->mode!=CONNECTING) {
		tcpClose(eptr->sock);

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
	}

	SAFE_DELETE(eptr);
	CMasterConn::s_Instance = NULL;

	free(MasterHost);
	free(MasterPort);
	free(BindHost);
}

void masterconn_connected(CMasterConn *eptr) {
	tcpNoDelay(eptr->sock);
	eptr->mode=HEADER;
	eptr->inputpacket.next = NULL;
	eptr->inputpacket.bytesleft = 8;
	eptr->inputpacket.startptr = eptr->hdrbuff;
	eptr->inputpacket.packet = NULL;
	eptr->outputhead = NULL;
	eptr->outputtail = &(eptr->outputhead);

	masterconn_sendregister(eptr);
	eptr->lastread = eptr->lastwrite = CServerCore::get_time();
}

int masterconn_initconnect(CMasterConn *eptr) {
	int status;
	if (eptr->masteraddrvalid==0) {
		uint32_t mip,bip;
		uint16_t mport;
		if (tcpResolve(BindHost,NULL,&bip,NULL,1)<0) {
			bip = 0;
		}
		eptr->bindip = bip;
		if (tcpResolve(MasterHost,MasterPort,&mip,&mport,0)>=0) {
			if ((mip&0xFF000000)!=0x7F000000) {
				eptr->masterip = mip;
				eptr->masterport = mport;
				eptr->masteraddrvalid = 1;
			} else {
				mfs_arg_syslog(LOG_WARNING,"master connection module: localhost (%u.%u.%u.%u) can't be used for connecting with master (use ip address of network controller)",(mip>>24)&0xFF,(mip>>16)&0xFF,(mip>>8)&0xFF,mip&0xFF);
				return -1;
			}
		} else {
			mfs_arg_syslog(LOG_WARNING,"master connection module: can't resolve master host/port (%s:%s)",MasterHost,MasterPort);
			return -1;
		}
	}

	eptr->sock=tcpSocket();
	if (eptr->sock<0) {
		mfs_errlog(LOG_WARNING,"master connection module: create socket error");
		return -1;
	}
	if (tcpNonBlock(eptr->sock)<0) {
		mfs_errlog(LOG_WARNING,"master connection module: set nonblock error");
		tcpClose(eptr->sock);
		eptr->sock = -1;
		return -1;
	}
	if (eptr->bindip>0) {
		if (tcpNumBind(eptr->sock,eptr->bindip,0)<0) {
			mfs_errlog(LOG_WARNING,"master connection module: can't bind socket to given ip");
			tcpClose(eptr->sock);
			eptr->sock = -1;
			return -1;
		}
	}

	status = tcpNumConnect(eptr->sock,eptr->masterip,eptr->masterport);
	if (status<0) {
		mfs_errlog(LOG_WARNING,"master connection module: connect failed");
		tcpClose(eptr->sock);
		eptr->sock = -1;
		eptr->masteraddrvalid = 0;
		return -1;
	}
	if (status==0) {
		syslog(LOG_NOTICE,"connected to Master immediately");
		masterconn_connected(eptr);
	} else {
		eptr->mode = CONNECTING;
		syslog(LOG_NOTICE,"connecting ...");
	}

	return 0;
}

void masterconn_connecttest(CMasterConn *eptr) {
	int status;

	status = tcpGetStatus(eptr->sock);
	if (status) {
		mfs_errlog_silent(LOG_WARNING,"connection failed, error");
		tcpClose(eptr->sock);
		eptr->sock = -1;
		eptr->mode = FREE;
		eptr->masteraddrvalid = 0;
	} else {
		syslog(LOG_NOTICE,"connected to Master");
		masterconn_connected(eptr);
	}
}

void masterconn_read(CMasterConn *eptr) {
	int32_t i;
	uint32_t type,size;
	const uint8_t *ptr;
	for (;;) {
#ifdef BGJOBS
		if (job_pool_jobs_count(jpool)>=(BGJOBSCNT*9)/10) {
			return;
		}
#endif
		i=read(eptr->sock,eptr->inputpacket.startptr,eptr->inputpacket.bytesleft);
		if (i==0) {
			syslog(LOG_NOTICE,"connection reset by Master");
			eptr->mode = KILL;
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"read from Master error");
				eptr->mode = KILL;
			}
			return;
		}
		stats_bytesin+=i;
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
					syslog(LOG_WARNING,"Master packet too long (%"PRIu32"/%u)",size,MaxPacketSize);
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

			masterconn_gotpacket(eptr,type,eptr->inputpacket.packet,size);

			if (eptr->inputpacket.packet) {
				free(eptr->inputpacket.packet);
			}
			eptr->inputpacket.packet=NULL;
		}
	}
}

void masterconn_write(CMasterConn *eptr) {
	packetStruct *pack;
	int32_t i;
	for (;;) {
		pack = eptr->outputhead;
		if (pack==NULL) {
			return;
		}
		i=write(eptr->sock,pack->startptr,pack->bytesleft);
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_errlog_silent(LOG_NOTICE,"write to Master error");
				eptr->mode = KILL;
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
	}
}


void masterconn_desc(struct pollfd *pdesc,uint32_t *ndesc) {
	uint32_t pos = *ndesc;
	CMasterConn *eptr = CMasterConn::s_Instance;

	eptr->pdescpos = -1;
	jobFdPdescPos = -1;

	if (eptr->mode==FREE || eptr->sock<0) {
		return;
	}
	if (eptr->mode==HEADER || eptr->mode==DATA) {
#ifdef BGJOBS
		pdesc[pos].fd = jobfd;
		pdesc[pos].events = POLLIN;
		jobFdPdescPos = pos;
		pos++;

		if (job_pool_jobs_count(jpool)<(BGJOBSCNT*9)/10) {
			pdesc[pos].fd = eptr->sock;
			pdesc[pos].events = POLLIN;
			eptr->pdescpos = pos;
			pos++;
		}
#else /* BGJOBS */
		pdesc[pos].fd = eptr->sock;
		pdesc[pos].events = POLLIN;
		eptr->pdescpos = pos;
		pos++;
#endif /* BGJOBS */
	}
	if (((eptr->mode==HEADER || eptr->mode==DATA) && eptr->outputhead!=NULL) || eptr->mode==CONNECTING) {
		if (eptr->pdescpos>=0) {
			pdesc[eptr->pdescpos].events |= POLLOUT;
		} else {
			pdesc[pos].fd = eptr->sock;
			pdesc[pos].events = POLLOUT;
			eptr->pdescpos = pos;
			pos++;
		}
	}
	*ndesc = pos;
}

void masterconn_serve(struct pollfd *pdesc) {
	uint32_t now=CServerCore::get_time();
	packetStruct *pptr,*paptr;
	CMasterConn *eptr = CMasterConn::s_Instance;

	if (eptr->pdescpos>=0 && (pdesc[eptr->pdescpos].revents & (POLLHUP | POLLERR))) {
		if (eptr->mode==CONNECTING) {
			masterconn_connecttest(eptr);
		} else {
			eptr->mode = KILL;
		}
	}
	if (eptr->mode==CONNECTING) {
		if (eptr->sock>=0 && eptr->pdescpos>=0 && (pdesc[eptr->pdescpos].revents & POLLOUT)) { // FD_ISSET(eptr->sock,wset)) {
			masterconn_connecttest(eptr);
		}
	} else {
#ifdef BGJOBS
		if ((eptr->mode==HEADER || eptr->mode==DATA) && jobFdPdescPos>=0 && (pdesc[jobFdPdescPos].revents & POLLIN)) { // FD_ISSET(jobfd,rset)) {
			job_pool_check_jobs(jpool);
		}
#endif /* BGJOBS */
		if (eptr->pdescpos>=0) {
			if ((eptr->mode==HEADER || eptr->mode==DATA) && (pdesc[eptr->pdescpos].revents & POLLIN)) { // FD_ISSET(eptr->sock,rset)) {
				eptr->lastread = now;
				masterconn_read(eptr);
			}
			if ((eptr->mode==HEADER || eptr->mode==DATA) && (pdesc[eptr->pdescpos].revents & POLLOUT)) { // FD_ISSET(eptr->sock,wset)) {
				eptr->lastwrite = now;
				masterconn_write(eptr);
			}
			if ((eptr->mode==HEADER || eptr->mode==DATA) && eptr->lastread+Timeout<now) {
				eptr->mode = KILL;
			}
			if ((eptr->mode==HEADER || eptr->mode==DATA) && eptr->lastwrite+(Timeout/3)<now && eptr->outputhead==NULL) {
				eptr->createPacket(ANTOAN_NOP,0);
			}
		}
	}
#ifdef BGJOBS
	if (eptr->mode==HEADER || eptr->mode==DATA) {
		uint32_t jobscnt = job_pool_jobs_count(jpool);
		if (jobscnt>=stats_maxjobscnt) {
			stats_maxjobscnt=jobscnt;
		}
	}
#endif
	if (eptr->mode == KILL) {
#ifdef BGJOBS
		job_pool_disable_and_change_callback_all(jpool,masterconn_unwantedjobfinished);
#endif /* BGJOBS */
		tcpClose(eptr->sock);
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
		eptr->mode = FREE;
	}
}

void masterconn_reconnect(void) {
	CMasterConn *eptr = CMasterConn::s_Instance;
	if (eptr->mode==FREE) {
		masterconn_initconnect(eptr);
	}
}

void masterconn_reload(void) {
	CMasterConn *eptr = CMasterConn::s_Instance;
	uint32_t ReconnectionDelay;

	free(MasterHost);
	free(MasterPort);
	free(BindHost);

	MasterHost = cfg_getstr("MASTER_HOST","mfsmaster");
	MasterPort = cfg_getstr("MASTER_PORT","9420");
	BindHost = cfg_getstr("BIND_HOST","*");

	if (eptr->masteraddrvalid && eptr->mode!=FREE) {
		uint32_t mip,bip;
		uint16_t mport;
		if (tcpResolve(BindHost,NULL,&bip,NULL,1)<0) {
			bip = 0;
		}
		if (eptr->bindip!=bip) {
			eptr->bindip = bip;
			eptr->mode = KILL;
		}
		if (tcpResolve(MasterHost,MasterPort,&mip,&mport,0)>=0) {
			if ((mip&0xFF000000)!=0x7F000000) {
				if (eptr->masterip!=mip || eptr->masterport!=mport) {
					eptr->masterip = mip;
					eptr->masterport = mport;
					eptr->mode = KILL;
				}
			} else {
				mfs_arg_syslog(LOG_WARNING,"master connection module: localhost (%u.%u.%u.%u) can't be used for connecting with master (use ip address of network controller)",(mip>>24)&0xFF,(mip>>16)&0xFF,(mip>>8)&0xFF,mip&0xFF);
			}
		} else {
			mfs_arg_syslog(LOG_WARNING,"master connection module: can't resolve master host/port (%s:%s)",MasterHost,MasterPort);
		}
	} else {
		eptr->masteraddrvalid=0;
	}

	Timeout = cfg_getuint32("MASTER_TIMEOUT",60);

	ReconnectionDelay = cfg_getuint32("MASTER_RECONNECTION_DELAY",5);

	if (Timeout>65536) {
		Timeout=65535;
	}
	if (Timeout<10) {
		Timeout=10;
	}

	CServerCore::getInstance()->time_change(reconnect_hook,TIMEMODE_RUN_LATE,ReconnectionDelay,0);
}

int masterconn_init(void) {
	uint32_t ReconnectionDelay;
	CMasterConn *eptr;

	ReconnectionDelay = cfg_getuint32("MASTER_RECONNECTION_DELAY",5);
	MasterHost = cfg_getstr("MASTER_HOST","mfsmaster");
	MasterPort = cfg_getstr("MASTER_PORT","9420");
	BindHost = cfg_getstr("BIND_HOST","*");
	Timeout = cfg_getuint32("MASTER_TIMEOUT",60);

	if (Timeout>65536) {
		Timeout=65535;
	}
	if (Timeout<10) {
		Timeout=10;
	}
	eptr = CMasterConn::s_Instance = new CMasterConn();
	passert(eptr);

	eptr->masteraddrvalid = 0;
	eptr->mode = FREE;
	eptr->pdescpos = -1;

	if (masterconn_initconnect(eptr)<0) {
		return -1;
	}

#ifdef BGJOBS
	jpool = job_pool_new(10,BGJOBSCNT,&jobfd);
	if (jpool==NULL) {
		return -1;
	}
#endif

	CServerCore::getInstance()->eachloop_register(masterconn_check_hdd_reports);
	reconnect_hook = CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,ReconnectionDelay,rndu32_ranged(ReconnectionDelay),masterconn_reconnect);
	CServerCore::getInstance()->destruct_register(masterconn_term);
	CServerCore::getInstance()->poll_register(masterconn_desc,masterconn_serve);
	CServerCore::getInstance()->reload_register(masterconn_reload);

	return 0;
}
