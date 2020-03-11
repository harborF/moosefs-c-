#include "config.h"

#include <time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>

#include "cfg.h"
#include "MetaLoggerConn.h"
#include "MetaLoggerCtrl.h"
#include "ServerCore.h"
#include "sockets.h"
#include "slogger.h"

#define MaxPacketSize 1500000


static int lsock;
static int32_t lsockpdescpos;

// from config
static char *ListenHost;
static char *ListenPort;

void matomlserv_broadcast_logstring(uint64_t version,uint8_t *logstr,uint32_t logstrsize)
{
	uint8_t *data;

	CMetaLoggerConn::store_logstring(version,logstr,logstrsize);

	for (CMetaLoggerConn *eptr = CMetaLoggerConn::s_pServHead; eptr ; eptr=eptr->next) {
		if (eptr->version>0) {
			data = eptr->createPacket(MATOML_METACHANGES_LOG,9+logstrsize);
			put8bit(&data,0xFF);
			put64bit(&data,version);
			memcpy(data,logstr,logstrsize);
		}
	}
}

void matomlserv_broadcast_logrotate() {
	uint8_t *data;

	for (CMetaLoggerConn *eptr = CMetaLoggerConn::s_pServHead ; eptr ; eptr=eptr->next) {
		if (eptr->version>0) {
			data = eptr->createPacket(MATOML_METACHANGES_LOG,1);
			put8bit(&data,0x55);
		}
	}
}

void matomlserv_gotpacket(CMetaLoggerConn *eptr,uint32_t type,const uint8_t *data,uint32_t length) {
	switch (type) {
		case ANTOAN_NOP:
			break;
		case ANTOAN_UNKNOWN_COMMAND: // for future use
			break;
		case ANTOAN_BAD_COMMAND_SIZE: // for future use
			break;
		case MLTOMA_REGISTER:
			eptr->serv_register(data,length);
			break;
		case MLTOMA_DOWNLOAD_START:
			eptr->download_start(data,length);
			break;
		case MLTOMA_DOWNLOAD_DATA:
			eptr->download_data(data,length);
			break;
		case MLTOMA_DOWNLOAD_END:
			eptr->download_end(data,length);
			break;
		default:
			syslog(LOG_NOTICE,"master <-> metaloggers module: got unknown message (type:%"PRIu32")",type);
			eptr->mode=KILL;
	}
}

void matomlserv_term(void) {
	CMetaLoggerConn *eptr,*eaptr;
	packetStruct *pptr,*paptr;
	syslog(LOG_INFO,"master <-> metaloggers module: closing %s:%s",ListenHost,ListenPort);
	tcpClose(lsock);

	eptr = CMetaLoggerConn::s_pServHead;
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
		eaptr = eptr;
		eptr = eptr->next;
		free(eaptr);
	}
	CMetaLoggerConn::s_pServHead=NULL;

	free(ListenHost);
	free(ListenPort);
}

void matomlserv_read(CMetaLoggerConn *eptr) {
	int32_t i;
	uint32_t type,size;
	const uint8_t *ptr;

    for (;;) {
		i=read(eptr->sock,eptr->inputpacket.startptr,eptr->inputpacket.bytesleft);
		if (i==0) {
			syslog(LOG_NOTICE,"connection with ML(%s) has been closed by peer",eptr->servstrip);
			eptr->mode = KILL;
			return;
		}
		if (i<0) {
			if (errno!=EAGAIN) {
				mfs_arg_errlog_silent(LOG_NOTICE,"read from ML(%s) error",eptr->servstrip);
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
					syslog(LOG_WARNING,"ML(%s) packet too long (%"PRIu32"/%u)",eptr->servstrip,size,MaxPacketSize);
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

			matomlserv_gotpacket(eptr,type,eptr->inputpacket.packet,size);

			if (eptr->inputpacket.packet) {
				free(eptr->inputpacket.packet);
			}
			eptr->inputpacket.packet=NULL;
		}
	}
}

void matomlserv_write(CMetaLoggerConn *eptr) {
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
				mfs_arg_errlog_silent(LOG_NOTICE,"write to ML(%s) error",eptr->servstrip);
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

void matomlserv_desc(struct pollfd *pdesc,uint32_t *ndesc) {
	uint32_t pos = *ndesc;
	CMetaLoggerConn *eptr;
	pdesc[pos].fd = lsock;
	pdesc[pos].events = POLLIN;
	lsockpdescpos = pos;
	pos++;

	for (eptr=CMetaLoggerConn::s_pServHead ; eptr ; eptr=eptr->next) {
		pdesc[pos].fd = eptr->sock;
		pdesc[pos].events = POLLIN;
		eptr->pdescpos = pos;
		if (eptr->outputhead!=NULL) {
			pdesc[pos].events |= POLLOUT;
		}
		pos++;
	}
	*ndesc = pos;
}

void matomlserv_serve(struct pollfd *pdesc) {
	uint32_t now=CServerCore::get_time();
	CMetaLoggerConn *eptr,**kptr;
	int ns;
	static uint64_t lastaction = 0;
	uint64_t unow;
	uint32_t timeoutadd;

	if (lastaction==0) {
		lastaction = CServerCore::get_precise_utime();
	}

	if (lsockpdescpos>=0 && (pdesc[lsockpdescpos].revents & POLLIN)) {
		ns=tcpAccept(lsock);
		if (ns<0) {
			mfs_errlog_silent(LOG_NOTICE,"Master<->ML socket: accept error");
		} else {
			tcpNonBlock(ns);
			tcpNoDelay(ns);
			eptr = (CMetaLoggerConn*)malloc(sizeof(CMetaLoggerConn));
			passert(eptr);
			eptr->next = CMetaLoggerConn::s_pServHead;
			CMetaLoggerConn::s_pServHead = eptr;
            
            eptr->init(ns, now);
			eptr->mode = HEADER;
            eptr->version=0;
			eptr->timeout = 10;

			tcpGetPeer(eptr->sock,&(eptr->servip),NULL);
			eptr->servstrip = CMetaLoggerConn::makestrip(eptr->servip);
			eptr->metafd=-1;
			eptr->chain1fd=-1;
			eptr->chain2fd=-1;
		}
	}

// read
	for (eptr=CMetaLoggerConn::s_pServHead ; eptr ; eptr=eptr->next) {
		if (eptr->pdescpos>=0) {
			if (pdesc[eptr->pdescpos].revents & (POLLERR|POLLHUP)) {
				eptr->mode = KILL;
			}
			if ((pdesc[eptr->pdescpos].revents & POLLIN) && eptr->mode!=KILL) {
				eptr->lastread = now;
				matomlserv_read(eptr);
			}
		}
	}

// timeout fix
	unow = CServerCore::get_precise_utime();
	timeoutadd = (unow-lastaction)/1000000;
	if (timeoutadd) {
		for (eptr=CMetaLoggerConn::s_pServHead; eptr ; eptr=eptr->next) {
			eptr->lastread += timeoutadd;
		}
	}
	lastaction = unow;

// write
	for (eptr=CMetaLoggerConn::s_pServHead; eptr ; eptr=eptr->next) {
		if ((uint32_t)(eptr->lastwrite+(eptr->timeout/3))<(uint32_t)now && eptr->outputhead==NULL) {
			eptr->createPacket(ANTOAN_NOP,0);
		}

		if (eptr->pdescpos>=0) {
			if ((((pdesc[eptr->pdescpos].events & POLLOUT)==0 && (eptr->outputhead))
                || (pdesc[eptr->pdescpos].revents & POLLOUT)) && eptr->mode!=KILL) {
				eptr->lastwrite = now;
				matomlserv_write(eptr);
			}
		}
		if ((uint32_t)(eptr->lastread+eptr->timeout)<(uint32_t)now) {
			eptr->mode = KILL;
		}
	}

// close
	kptr = &CMetaLoggerConn::s_pServHead;
	while ((eptr=*kptr)) {
		if (eptr->mode == KILL) {
			eptr->beforeclose();
			tcpClose(eptr->sock);
            eptr->clear();

			if (eptr->servstrip) {
				free(eptr->servstrip);
			}
			*kptr = eptr->next;
			free(eptr);
		} else {
			kptr = &(eptr->next);
		}
	}
}

void matomlserv_reload(void) {
	char *oldListenHost,*oldListenPort;
	int newlsock;

	oldListenHost = ListenHost;
	oldListenPort = ListenPort;
	ListenHost = cfg_getstr("MATOML_LISTEN_HOST","*");
	ListenPort = cfg_getstr("MATOML_LISTEN_PORT","9419");
	if (strcmp(oldListenHost,ListenHost)==0 && strcmp(oldListenPort,ListenPort)==0) {
		free(oldListenHost);
		free(oldListenPort);
		mfs_arg_syslog(LOG_NOTICE,"master <-> metaloggers module: socket address hasn't changed (%s:%s)",ListenHost,ListenPort);
		return;
	}

	newlsock = tcpSocket();
	if (newlsock<0) {
		mfs_errlog(LOG_WARNING,"master <-> metaloggers module: socket address has changed, but can't create new socket");
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
		mfs_errlog_silent(LOG_NOTICE,"master <-> metaloggers module: can't set accept filter");
	}
	if (tcpStrListen(newlsock,ListenHost,ListenPort,100)<0) {
		mfs_arg_errlog(LOG_ERR,"master <-> metaloggers module: socket address has changed, but can't listen on socket (%s:%s)",ListenHost,ListenPort);
		free(ListenHost);
		free(ListenPort);
		ListenHost = oldListenHost;
		ListenPort = oldListenPort;
		tcpClose(newlsock);
		return;
	}

	mfs_arg_syslog(LOG_NOTICE,"master <-> metaloggers module: socket address has changed, now listen on %s:%s",ListenHost,ListenPort);
	free(oldListenHost);
	free(oldListenPort);
	tcpClose(lsock);
	lsock = newlsock;

	CMetaLoggerConn::s_changelog_save = cfg_getuint16("MATOML_LOG_PRESERVE_SECONDS",600);
	if (CMetaLoggerConn::s_changelog_save>3600) {
		syslog(LOG_WARNING,"Number of seconds of change logs to be preserved in master is too big (%"PRIu16") - decreasing to 3600 seconds",CMetaLoggerConn::s_changelog_save);
		CMetaLoggerConn::s_changelog_save=3600;
	}
}

int matomlserv_init(void) {
	ListenHost = cfg_getstr("MATOML_LISTEN_HOST","*");
	ListenPort = cfg_getstr("MATOML_LISTEN_PORT","9419");

	lsock = tcpSocket();
	if (lsock<0) {
		mfs_errlog(LOG_ERR,"master <-> metaloggers module: can't create socket");
		return -1;
	}

	tcpNonBlock(lsock);
	tcpNoDelay(lsock);
	tcpReuseAddr(lsock);

	if (tcpSetAcceptFilter(lsock)<0 && errno!=ENOTSUP) {
		mfs_errlog_silent(LOG_NOTICE,"master <-> metaloggers module: can't set accept filter");
	}

	if (tcpStrListen(lsock,ListenHost,ListenPort,100)<0) {
		mfs_arg_errlog(LOG_ERR,"master <-> metaloggers module: can't listen on %s:%s",ListenHost,ListenPort);
		return -1;
	}

	mfs_arg_syslog(LOG_NOTICE,"master <-> metaloggers module: listen on %s:%s",ListenHost,ListenPort);

	CMetaLoggerConn::s_pServHead = NULL;
	CMetaLoggerConn::s_changelog_save = cfg_getuint16("MATOML_LOG_PRESERVE_SECONDS",600);
	if (CMetaLoggerConn::s_changelog_save>3600) {
		syslog(LOG_WARNING,"Number of seconds of change logs to be preserved in master is too big (%"PRIu16") - decreasing to 3600 seconds", CMetaLoggerConn::s_changelog_save);
		CMetaLoggerConn::s_changelog_save=3600;
	}

	CServerCore::getInstance()->reload_register(matomlserv_reload);
	CServerCore::getInstance()->destruct_register(matomlserv_term);
	CServerCore::getInstance()->poll_register(matomlserv_desc,matomlserv_serve);
	CServerCore::getInstance()->time_register(TIMEMODE_SKIP_LATE,3600,0, CMetaLoggerConn::serv_status);

	return 0;
}
