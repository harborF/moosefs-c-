#include "config.h"

#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <netinet/in.h>

#include "MasterConn.h"
#include "crc.h"
#include "cfg.h"
#include "ServerCore.h"
#include "sockets.h"

#define MaxPacketSize 1500000
#define META_DL_BLOCK 1000000

CMasterConn* CMasterConn::s_Instance = NULL;

// from config
static uint32_t BackLogsNumber;
static uint32_t BackMetaCopies;
static char *MasterHost;
static char *MasterPort;
static char *BindHost;
static uint32_t Timeout;
static void* reconnect_hook;
static void* download_hook;
static uint64_t lastlogversion=0;

static uint32_t stats_bytesout=0;
static uint32_t stats_bytesin=0;

void masterconn_stats(uint32_t *bin,uint32_t *bout) {
	*bin = stats_bytesin;
	*bout = stats_bytesout;
	stats_bytesin = 0;
	stats_bytesout = 0;
}

void masterconn_findlastlogversion(void) {
	struct stat st;
	uint8_t buff[32800];	// 32800 = 32768 + 32
	uint64_t size;
	uint32_t buffpos;
	uint64_t lastnewline;
	int fd;

	lastlogversion = 0;

	if (stat("metadata_ml.mfs.back",&st)<0 || st.st_size==0 || (st.st_mode & S_IFMT)!=S_IFREG) {
		return;
	}

	fd = open("changelog_ml.0.back",O_RDWR);
	if (fd<0) {
		return;
	}
	fstat(fd,&st);
	size = st.st_size;
	memset(buff,0,32);
	lastnewline = 0;
	while (size>0 && size+200000>(uint64_t)(st.st_size)) {
		if (size>32768) {
			memcpy(buff+32768,buff,32);
			size-=32768;
			lseek(fd,size,SEEK_SET);
			if (read(fd,buff,32768)!=32768) {
				lastlogversion = 0;
				close(fd);
				return;
			}
			buffpos = 32768;
		} else {
			memmove(buff+size,buff,32);
			lseek(fd,0,SEEK_SET);
			if (read(fd,buff,size)!=(ssize_t)size) {
				lastlogversion = 0;
				close(fd);
				return;
			}
			buffpos = size;
			size = 0;
		}
		// size = position in file of first byte in buff
		// buffpos = position of last byte in buff to search
		while (buffpos>0) {
			buffpos--;
			if (buff[buffpos]=='\n') {
				if (lastnewline==0) {
					lastnewline = size + buffpos;
				} else {
					if (lastnewline+1 != (uint64_t)(st.st_size)) {	// garbage at the end of file - truncate
						if (ftruncate(fd,lastnewline+1)<0) {
							lastlogversion = 0;
							close(fd);
							return;
						}
					}
					buffpos++;
					while (buffpos<32800 && buff[buffpos]>='0' && buff[buffpos]<='9') {
						lastlogversion *= 10;
						lastlogversion += buff[buffpos]-'0';
						buffpos++;
					}
					if (buffpos==32800 || buff[buffpos]!=':') {
						lastlogversion = 0;
					}
					close(fd);
					return;
				}
			}
		}
	}
	close(fd);
	return;
}

void masterconn_sendregister(CMasterConn *eptr) {
	uint8_t *buff;

	eptr->downloading=0;
	eptr->metafd=-1;
	eptr->logfd=NULL;

	if (lastlogversion>0) {
		buff = eptr->createPacket(MLTOMA_REGISTER,1+4+2+8);
		put8bit(&buff,2);
		put16bit(&buff,VERSMAJ);
		put8bit(&buff,VERSMID);
		put8bit(&buff,VERSMIN);
		put16bit(&buff,Timeout);
		put64bit(&buff,lastlogversion);
	} else {
		buff = eptr->createPacket(MLTOMA_REGISTER,1+4+2);
		put8bit(&buff,1);
		put16bit(&buff,VERSMAJ);
		put8bit(&buff,VERSMID);
		put8bit(&buff,VERSMIN);
		put16bit(&buff,Timeout);
	}
}

void masterconn_metachanges_log(CMasterConn *eptr,const uint8_t *data,uint32_t length) {
	char logname1[100],logname2[100];
	uint32_t i;
	uint64_t version;
	if (length==1 && data[0]==0x55) {
		if (eptr->logfd!=NULL) {
			fclose(eptr->logfd);
			eptr->logfd=NULL;
		}
		if (BackLogsNumber>0) {
			for (i=BackLogsNumber ; i>0 ; i--) {
				snprintf(logname1,100,"changelog_ml.%"PRIu32".mfs",i);
				snprintf(logname2,100,"changelog_ml.%"PRIu32".mfs",i-1);
				rename(logname2,logname1);
			}
		} else {
			unlink("changelog_ml.0.mfs");
		}
		return;
	}
	if (length<10) {
		syslog(LOG_NOTICE,"MATOML_METACHANGES_LOG - wrong size (%"PRIu32"/9+data)",length);
		eptr->mode = KILL;
		return;
	}
	if (data[0]!=0xFF) {
		syslog(LOG_NOTICE,"MATOML_METACHANGES_LOG - wrong packet");
		eptr->mode = KILL;
		return;
	}
	if (data[length-1]!='\0') {
		syslog(LOG_NOTICE,"MATOML_METACHANGES_LOG - invalid string");
		eptr->mode = KILL;
		return;
	}

	data++;
	version = get64bit(&data);

	if (lastlogversion>0 && version!=lastlogversion+1) {
		syslog(LOG_WARNING, "some changes lost: [%"PRIu64"-%"PRIu64"], download metadata again",lastlogversion,version-1);
		if (eptr->logfd!=NULL) {
			fclose(eptr->logfd);
			eptr->logfd=NULL;
		}
		for (i=0 ; i<=BackLogsNumber ; i++) {
			snprintf(logname1,100,"changelog_ml.%"PRIu32".mfs",i);
			unlink(logname1);
		}
		lastlogversion = 0;
		eptr->mode = KILL;
		return;
	}

	if (eptr->logfd==NULL) {
		eptr->logfd = fopen("changelog_ml.0.mfs","a");
	}

	if (eptr->logfd) {
		fprintf(eptr->logfd,"%"PRIu64": %s\n",version,data);
		lastlogversion = version;
	} else {
		syslog(LOG_NOTICE,"lost MFS change %"PRIu64": %s",version,data);
	}
}

void masterconn_metachanges_flush(void) {
	CMasterConn *eptr = CMasterConn::s_Instance;
	if (eptr->logfd) {
		fflush(eptr->logfd);
	}
}

int masterconn_download_end(CMasterConn *eptr) {
	eptr->downloading=0;
	eptr->createPacket(MLTOMA_DOWNLOAD_END,0);
	if (eptr->metafd>=0) {
		if (close(eptr->metafd)<0) {
			mfs_errlog_silent(LOG_NOTICE,"error closing metafile");
			eptr->metafd=-1;
			return -1;
		}
		eptr->metafd=-1;
	}
	return 0;
}

void masterconn_download_init(CMasterConn *eptr,uint8_t filenum) {
	uint8_t *ptr;
//	syslog(LOG_NOTICE,"download_init %d",filenum);
	if ((eptr->mode==HEADER || eptr->mode==DATA) && eptr->downloading==0) {
//		syslog(LOG_NOTICE,"sending packet");
		ptr = eptr->createPacket(MLTOMA_DOWNLOAD_START,1);
		put8bit(&ptr,filenum);
		eptr->downloading=filenum;
	}
}

void masterconn_metadownloadinit(void) {
	masterconn_download_init(CMasterConn::s_Instance,1);
}

void masterconn_sessionsdownloadinit(void) {
	masterconn_download_init(CMasterConn::s_Instance,2);
}

int masterconn_metadata_check(const char *name) {
	int fd;
	char chkbuff[16];
	char eofmark[16];
	fd = open(name,O_RDONLY);
	if (fd<0) {
		syslog(LOG_WARNING,"can't open downloaded metadata");
		return -1;
	}
	if (read(fd,chkbuff,8)!=8) {
		syslog(LOG_WARNING,"can't read downloaded metadata");
		close(fd);
		return -1;
	}
	if (memcmp(chkbuff,"MFSM NEW",8)==0) { // silently ignore "new file"
		close(fd);
		return -1;
	}
	if (memcmp(chkbuff,MFSSIGNATURE "M 1.5",8)==0) {
		memset(eofmark,0,16);
	} else if (memcmp(chkbuff,MFSSIGNATURE "M 1.7",8)==0) {
		memcpy(eofmark,"[MFS EOF MARKER]",16);
	} else {
		syslog(LOG_WARNING,"bad metadata file format");
		close(fd);
		return -1;
	}
	lseek(fd,-16,SEEK_END);
	if (read(fd,chkbuff,16)!=16) {
		syslog(LOG_WARNING,"can't read downloaded metadata");
		close(fd);
		return -1;
	}
	close(fd);
	if (memcmp(chkbuff,eofmark,16)!=0) {
		syslog(LOG_WARNING,"truncated metadata file !!!");
		return -1;
	}
	return 0;
}

void masterconn_download_next(CMasterConn *eptr) {
	uint8_t *ptr;
	uint8_t filenum;
	int64_t dltime;
	if (eptr->dloffset>=eptr->filesize) {	// end of file
		filenum = eptr->downloading;
		if (masterconn_download_end(eptr)<0) {
			return;
		}
		dltime = CServerCore::get_utime()-eptr->dlstartuts;
		if (dltime<=0) {
			dltime=1;
		}
		syslog(LOG_NOTICE,"%s downloaded %"PRIu64"B/%"PRIu64".%06"PRIu32"s (%.3lf MB/s)",(filenum==1)?"metadata":(filenum==2)?"sessions":(filenum==11)?"changelog_0":(filenum==12)?"changelog_1":"???",eptr->filesize,dltime/1000000,(uint32_t)(dltime%1000000),(double)(eptr->filesize)/(double)(dltime));
		if (filenum==1) {
			if (masterconn_metadata_check("metadata_ml.tmp")==0) {
				if (BackMetaCopies>0) {
					char metaname1[100],metaname2[100];
					int i;
					for (i=BackMetaCopies-1 ; i>0 ; i--) {
						snprintf(metaname1,100,"metadata_ml.mfs.back.%"PRIu32,i+1);
						snprintf(metaname2,100,"metadata_ml.mfs.back.%"PRIu32,i);
						rename(metaname2,metaname1);
					}
					rename("metadata_ml.mfs.back","metadata_ml.mfs.back.1");
				}
				if (rename("metadata_ml.tmp","metadata_ml.mfs.back")<0) {
					syslog(LOG_NOTICE,"can't rename downloaded metadata - do it manually before next download");
				}
			}
			if (eptr->oldmode==0) {
				masterconn_download_init(eptr,11);
			} else {
				masterconn_download_init(eptr,2);
			}
		} else if (filenum==11) {
			if (rename("changelog_ml.tmp","changelog_ml_back.0.mfs")<0) {
				syslog(LOG_NOTICE,"can't rename downloaded changelog - do it manually before next download");
			}
			masterconn_download_init(eptr,12);
		} else if (filenum==12) {
			if (rename("changelog_ml.tmp","changelog_ml_back.1.mfs")<0) {
				syslog(LOG_NOTICE,"can't rename downloaded changelog - do it manually before next download");
			}
			masterconn_download_init(eptr,2);
		} else if (filenum==2) {
			if (rename("sessions_ml.tmp","sessions_ml.mfs")<0) {
				syslog(LOG_NOTICE,"can't rename downloaded sessions - do it manually before next download");
			}
		}
	} else {	// send request for next data packet
		ptr = eptr->createPacket(MLTOMA_DOWNLOAD_DATA,12);
		put64bit(&ptr,eptr->dloffset);
		if (eptr->filesize-eptr->dloffset>META_DL_BLOCK) {
			put32bit(&ptr,META_DL_BLOCK);
		} else {
			put32bit(&ptr,eptr->filesize-eptr->dloffset);
		}
	}
}

void masterconn_download_start(CMasterConn *eptr,const uint8_t *data,uint32_t length) {
	if (length!=1 && length!=8) {
		syslog(LOG_NOTICE,"MATOML_DOWNLOAD_START - wrong size (%"PRIu32"/1|8)",length);
		eptr->mode = KILL;
		return;
	}
	passert(data);
	if (length==1) {
		eptr->downloading=0;
		syslog(LOG_NOTICE,"download start error");
		return;
	}
	eptr->filesize = get64bit(&data);
	eptr->dloffset = 0;
	eptr->downloadretrycnt = 0;
	eptr->dlstartuts = CServerCore::get_utime();
	if (eptr->downloading==1) {
		eptr->metafd = open("metadata_ml.tmp",O_WRONLY | O_TRUNC | O_CREAT,0666);
	} else if (eptr->downloading==2) {
		eptr->metafd = open("sessions_ml.tmp",O_WRONLY | O_TRUNC | O_CREAT,0666);
	} else if (eptr->downloading==11 || eptr->downloading==12) {
		eptr->metafd = open("changelog_ml.tmp",O_WRONLY | O_TRUNC | O_CREAT,0666);
	} else {
		syslog(LOG_NOTICE,"unexpected MATOML_DOWNLOAD_START packet");
		eptr->mode = KILL;
		return;
	}
	if (eptr->metafd<0) {
		mfs_errlog_silent(LOG_NOTICE,"error opening metafile");
		masterconn_download_end(eptr);
		return;
	}
	masterconn_download_next(eptr);
}

void masterconn_download_data(CMasterConn *eptr,const uint8_t *data,uint32_t length) {
	uint64_t offset;
	uint32_t leng;
	uint32_t crc;
	ssize_t ret;
	if (eptr->metafd<0) {
		syslog(LOG_NOTICE,"MATOML_DOWNLOAD_DATA - file not opened");
		eptr->mode = KILL;
		return;
	}
	if (length<16) {
		syslog(LOG_NOTICE,"MATOML_DOWNLOAD_DATA - wrong size (%"PRIu32"/16+data)",length);
		eptr->mode = KILL;
		return;
	}
	passert(data);
	offset = get64bit(&data);
	leng = get32bit(&data);
	crc = get32bit(&data);
	if (leng+16!=length) {
		syslog(LOG_NOTICE,"MATOML_DOWNLOAD_DATA - wrong size (%"PRIu32"/16+%"PRIu32")",length,leng);
		eptr->mode = KILL;
		return;
	}
	if (offset!=eptr->dloffset) {
		syslog(LOG_NOTICE,"MATOML_DOWNLOAD_DATA - unexpected file offset (%"PRIu64"/%"PRIu64")",offset,eptr->dloffset);
		eptr->mode = KILL;
		return;
	}
	if (offset+leng>eptr->filesize) {
		syslog(LOG_NOTICE,"MATOML_DOWNLOAD_DATA - unexpected file size (%"PRIu64"/%"PRIu64")",offset+leng,eptr->filesize);
		eptr->mode = KILL;
		return;
	}
#ifdef HAVE_PWRITE
	ret = pwrite(eptr->metafd,data,leng,offset);
#else /* HAVE_PWRITE */
	lseek(eptr->metafd,offset,SEEK_SET);
	ret = write(eptr->metafd,data,leng);
#endif /* HAVE_PWRITE */
	if (ret!=(ssize_t)leng) {
		mfs_errlog_silent(LOG_NOTICE,"error writing metafile");
		if (eptr->downloadretrycnt>=5) {
			masterconn_download_end(eptr);
		} else {
			eptr->downloadretrycnt++;
			masterconn_download_next(eptr);
		}
		return;
	}
	if (crc!=mycrc32(0,data,leng)) {
		syslog(LOG_NOTICE,"metafile data crc error");
		if (eptr->downloadretrycnt>=5) {
			masterconn_download_end(eptr);
		} else {
			eptr->downloadretrycnt++;
			masterconn_download_next(eptr);
		}
		return;
	}
	if (fsync(eptr->metafd)<0) {
		mfs_errlog_silent(LOG_NOTICE,"error syncing metafile");
		if (eptr->downloadretrycnt>=5) {
			masterconn_download_end(eptr);
		} else {
			eptr->downloadretrycnt++;
			masterconn_download_next(eptr);
		}
		return;
	}
	eptr->dloffset+=leng;
	eptr->downloadretrycnt=0;
	masterconn_download_next(eptr);
}

void masterconn_beforeclose(CMasterConn *eptr) {
	if (eptr->downloading==11 || eptr->downloading==12) {	// old (version less than 1.6.18) master patch
		syslog(LOG_WARNING,"old master detected - please upgrade your master server and then restart metalogger");
		eptr->oldmode=1;
	}
	if (eptr->metafd>=0) {
		close(eptr->metafd);
		eptr->metafd=-1;
		unlink("metadata_ml.tmp");
		unlink("sessions_ml.tmp");
		unlink("changelog_ml.tmp");
	}
	if (eptr->logfd) {
		fclose(eptr->logfd);
		eptr->logfd = NULL;
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
		case MATOML_METACHANGES_LOG:
			masterconn_metachanges_log(eptr,data,length);
			break;
		case MATOML_DOWNLOAD_START:
			masterconn_download_start(eptr,data,length);
			break;
		case MATOML_DOWNLOAD_DATA:
			masterconn_download_data(eptr,data,length);
			break;
		default:
			syslog(LOG_NOTICE,"got unknown message (type:%"PRIu32")",type);
			eptr->mode = KILL;
	}
}

void masterconn_term(void) {
	packetStruct *pptr,*paptr;
	CMasterConn *eptr = CMasterConn::s_Instance;

	if (eptr->mode!=FREE) {
		tcpClose(eptr->sock);
		if (eptr->mode!=CONNECTING) {
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
	}

	SAFE_DELETE(eptr);
	free(MasterHost);
	free(MasterPort);
	free(BindHost);
	CMasterConn::s_Instance = NULL;
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
	if (lastlogversion==0) {
		masterconn_metadownloadinit();
	}
	eptr->lastread = eptr->lastwrite = CServerCore::get_time();
}

int masterconn_initconnect(CMasterConn *eptr) {
	int status;
	if (eptr->masteraddrvalid==0) {
		uint32_t mip,bip;
		uint16_t mport;
		if (tcpResolve(BindHost,NULL,&bip,NULL,1)>=0) {
			eptr->bindip = bip;
		} else {
			eptr->bindip = 0;
		}
		if (tcpResolve(MasterHost,MasterPort,&mip,&mport,0)>=0) {
			eptr->masterip = mip;
			eptr->masterport = mport;
			eptr->masteraddrvalid = 1;
		} else {
			mfs_arg_syslog(LOG_WARNING,"can't resolve master host/port (%s:%s)",MasterHost,MasterPort);
			return -1;
		}
	}
	eptr->sock=tcpSocket();
	if (eptr->sock<0) {
		mfs_errlog(LOG_WARNING,"create socket, error");
		return -1;
	}
	if (tcpNonBlock(eptr->sock)<0) {
		mfs_errlog(LOG_WARNING,"set nonblock, error");
		tcpClose(eptr->sock);
		eptr->sock = -1;
		return -1;
	}
	if (eptr->bindip>0) {
		if (tcpNumBind(eptr->sock,eptr->bindip,0)<0) {
			mfs_errlog(LOG_WARNING,"can't bind socket to given ip");
			tcpClose(eptr->sock);
			eptr->sock = -1;
			return -1;
		}
	}
	status = tcpNumConnect(eptr->sock,eptr->masterip,eptr->masterport);
	if (status<0) {
		mfs_errlog(LOG_WARNING,"connect failed, error");
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
		i=read(eptr->sock,eptr->inputpacket.startptr,eptr->inputpacket.bytesleft);
		if (i==0) {
			syslog(LOG_NOTICE,"connection was reset by Master");
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
	if (eptr->mode==FREE || eptr->sock<0) {
		return;
	}
	if (eptr->mode==HEADER || eptr->mode==DATA) {
		pdesc[pos].fd = eptr->sock;
		pdesc[pos].events = POLLIN;
		eptr->pdescpos = pos;
		pos++;
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

void masterconn_serve(struct pollfd *pdesc)
{
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
		if (eptr->sock>=0 && eptr->pdescpos>=0 && (pdesc[eptr->pdescpos].revents & POLLOUT)) {
			masterconn_connecttest(eptr);
		}
    } else if (eptr->pdescpos>=0) {
        if ((eptr->mode==HEADER || eptr->mode==DATA) && (pdesc[eptr->pdescpos].revents & POLLIN)) {
            eptr->lastread = CServerCore::get_time();
            masterconn_read(eptr);
        }
        if ((eptr->mode==HEADER || eptr->mode==DATA) && (pdesc[eptr->pdescpos].revents & POLLOUT)) {
            eptr->lastwrite = CServerCore::get_time();
            masterconn_write(eptr);
        }
        if ((eptr->mode==HEADER || eptr->mode==DATA) && eptr->lastread+Timeout<CServerCore::get_time()) {
            eptr->mode = KILL;
        }
        if ((eptr->mode==HEADER || eptr->mode==DATA) && eptr->lastwrite+(Timeout/3)<CServerCore::get_time() && eptr->outputhead==NULL) {
            eptr->createPacket(ANTOAN_NOP,0);
        }
    }

	if (eptr->mode == KILL) {
		masterconn_beforeclose(eptr);
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
	uint32_t MetaDLFreq;

	free(MasterHost);
	free(MasterPort);
	free(BindHost);

	MasterHost = cfg_getstr("MASTER_HOST","mfsmaster");
	MasterPort = cfg_getstr("MASTER_PORT","9419");
	BindHost = cfg_getstr("BIND_HOST","*");

	eptr->masteraddrvalid = 0;
	if (eptr->mode!=FREE) {
		eptr->mode = KILL;
	}

	Timeout = cfg_getuint32("MASTER_TIMEOUT",60);
	BackLogsNumber = cfg_getuint32("BACK_LOGS",50);
	BackMetaCopies = cfg_getuint32("BACK_META_KEEP_PREVIOUS",3);

	ReconnectionDelay = cfg_getuint32("MASTER_RECONNECTION_DELAY",5);
	MetaDLFreq = cfg_getuint32("META_DOWNLOAD_FREQ",24);

	if (Timeout>65536) {
		Timeout=65535;
	}
	if (Timeout<10) {
		Timeout=10;
	}
	if (BackLogsNumber<5) {
		BackLogsNumber=5;
	}
	if (BackLogsNumber>10000) {
		BackLogsNumber=10000;
	}
	if (MetaDLFreq>(BackLogsNumber/2)) {
		MetaDLFreq=BackLogsNumber/2;
	}
	if (BackMetaCopies>99) {
		BackMetaCopies=99;
	}

	CServerCore::getInstance()->time_change(reconnect_hook,TIMEMODE_RUN_LATE,ReconnectionDelay,0);
	CServerCore::getInstance()->time_change(download_hook,TIMEMODE_RUN_LATE,MetaDLFreq*3600,630);
}

int masterconn_init(void) {
	uint32_t ReconnectionDelay;
	uint32_t MetaDLFreq;
	CMasterConn *eptr;

	ReconnectionDelay = cfg_getuint32("MASTER_RECONNECTION_DELAY",5);
	MasterHost = cfg_getstr("MASTER_HOST","mfsmaster");
	MasterPort = cfg_getstr("MASTER_PORT","9419");
	BindHost = cfg_getstr("BIND_HOST","*");
	Timeout = cfg_getuint32("MASTER_TIMEOUT",60);
	BackLogsNumber = cfg_getuint32("BACK_LOGS",50);
	BackMetaCopies = cfg_getuint32("BACK_META_KEEP_PREVIOUS",3);
	MetaDLFreq = cfg_getuint32("META_DOWNLOAD_FREQ",24);

	if (Timeout>65536) {
		Timeout=65535;
	}
	if (Timeout<10) {
		Timeout=10;
	}
	if (BackLogsNumber<5) {
		BackLogsNumber=5;
	}
	if (BackLogsNumber>10000) {
		BackLogsNumber=10000;
	}
	if (MetaDLFreq>(BackLogsNumber/2)) {
		MetaDLFreq=BackLogsNumber/2;
	}
	eptr = CMasterConn::s_Instance = new CMasterConn();
	passert(eptr);

	eptr->masteraddrvalid = 0;
	eptr->mode = FREE;
	eptr->pdescpos = -1;
	eptr->logfd = NULL;
	eptr->metafd = -1;
	eptr->oldmode = 0;

	masterconn_findlastlogversion();
	if (masterconn_initconnect(eptr)<0) {
		return -1;
	}

	reconnect_hook = CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,ReconnectionDelay,0,masterconn_reconnect);
	download_hook = CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,MetaDLFreq*3600,630,masterconn_metadownloadinit);
	CServerCore::getInstance()->destruct_register(masterconn_term);
	CServerCore::getInstance()->poll_register(masterconn_desc,masterconn_serve);
	CServerCore::getInstance()->reload_register(masterconn_reload);
	CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,60,0,masterconn_sessionsdownloadinit);
	CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,1,0,masterconn_metachanges_flush);

	return 0;
}
