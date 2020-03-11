#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>

#include "sockets.h"
#include "MasterComm.h"
#include "DataPack.h"

#define QUERYSIZE 10000
#define ANSSIZE 10000

static int s_lsock = -1;
static pthread_t proxythread;
static uint8_t s_terminate;

static uint32_t proxyhost;
static uint16_t proxyport;

void masterproxy_getlocation(uint8_t *masterinfo) {
	const uint8_t *rptr = masterinfo+10;
	if (s_lsock>=0 && get32bit(&rptr)>=0x00010618) {	// use proxy only when master version is greater than or equal to 1.6.24
		put32bit(&masterinfo,proxyhost);
		put16bit(&masterinfo,proxyport);
	}
}

static void* masterproxy_server(void *args) {
	uint8_t header[8];
	uint8_t querybuffer[QUERYSIZE];
	uint8_t ansbuffer[ANSSIZE];
	uint8_t *wptr;
	const uint8_t *rptr;
	int sock = *((int*)args);
	uint32_t psize,cmd,msgid,asize,acmd;

	free(args);

	for (;;) {
		if (tcpToRead(sock,header,8,1000)!=8) {
			tcpClose(sock);
			return NULL;
		}

		rptr = header;
		cmd = get32bit(&rptr);
		psize = get32bit(&rptr);
		if (cmd==CLTOMA_FUSE_REGISTER) {	// special case: register
			// if (psize>QUERYSIZE) {
			if (psize!=73) {
				tcpClose(sock);
				return NULL;
			}

			if (tcpToRead(sock,querybuffer,psize,1000)!=(int32_t)(psize)) {
				tcpClose(sock);
				return NULL;
			}

			if (memcmp(querybuffer,FUSE_REGISTER_BLOB_ACL,64)!=0) {
				tcpClose(sock);
				return NULL;
			}

			if (querybuffer[64]!=REGISTER_TOOLS) {
				tcpClose(sock);
				return NULL;
			}

			wptr = ansbuffer;
			put32bit(&wptr,MATOCL_FUSE_REGISTER);
			put32bit(&wptr,1);
			put8bit(&wptr,STATUS_OK);

			if (tcpToWrite(sock,ansbuffer,9,1000)!=9) {
				tcpClose(sock);
				return NULL;
			}
		} else {
			if (psize<4 || psize>QUERYSIZE) {
				tcpClose(sock);
				return NULL;
			}

			if (tcpToRead(sock,querybuffer,psize,1000)!=(int32_t)(psize)) {
				tcpClose(sock);
				return NULL;
			}

			rptr = querybuffer;
			msgid = get32bit(&rptr);

			asize = ANSSIZE-12;
			if (fs_custom(cmd,querybuffer+4,psize-4,&acmd,ansbuffer+12,&asize)!=STATUS_OK) {
				tcpClose(sock);
				return NULL;
			}

			wptr = ansbuffer;
			put32bit(&wptr,acmd);
			put32bit(&wptr,asize+4);
			put32bit(&wptr,msgid);

			if (tcpToWrite(sock,ansbuffer,asize+12,1000)!=(int32_t)(asize+12)) {
				tcpClose(sock);
				return NULL;
			}
		}//end if
	}//end for
}

static void* masterproxy_acceptor(void *args)
{
	pthread_t clientthread;
	pthread_attr_t thattr;
	int sock;
	(void)args;

	pthread_attr_init(&thattr);
	pthread_attr_setstacksize(&thattr,0x100000);
	pthread_attr_setdetachstate(&thattr,PTHREAD_CREATE_DETACHED);

	while (s_terminate==0) {
		sock = tcpToAccept(s_lsock,1000);
		if (sock>=0) {
			int *s = (int*)malloc(sizeof(int));
			// memory is freed inside pthread routine !!!
			*s = sock;
			tcpNoDelay(sock);
			if (pthread_create(&clientthread,&thattr,masterproxy_server,s)<0) {
				free(s);
				tcpClose(sock);
			}
		}
	}

	pthread_attr_destroy(&thattr);
	return NULL;
}

void masterproxy_term(void) {
	s_terminate=1;
	pthread_join(proxythread,NULL);
}

int masterproxy_init(void) {

	s_lsock = tcpSocket();
	if (s_lsock<0) {
		//mfs_errlog(LOG_ERR,"main master server module: can't create socket");
		return -1;
	}

	tcpNonBlock(s_lsock);
	tcpNoDelay(s_lsock);
	// tcpReuseAddr(s_lsock);
	if (tcpSetAcceptFilter(s_lsock)<0 && errno!=ENOTSUP) {
		// mfs_errlog_silent(LOG_NOTICE,"master proxy: can't set accept filter");
	}

	if (tcpStrListen(s_lsock,"127.0.0.1",0,100)<0) {
		// mfs_errlog(LOG_ERR,"main master server module: can't listen on socket");
		tcpClose(s_lsock);
		s_lsock = -1;
		return -1;
	}

	if (tcpGetMyAddr(s_lsock,&proxyhost,&proxyport)<0) {
		tcpClose(s_lsock);
		s_lsock = -1;
		return -1;
	}

	s_terminate = 0;

    pthread_attr_t thattr;
	pthread_attr_init(&thattr);
	pthread_attr_setstacksize(&thattr,0x100000);
	pthread_create(&proxythread,&thattr,masterproxy_acceptor,NULL);
	pthread_attr_destroy(&thattr);

	return 1;
}
