#include "config.h"

#include <time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <netinet/in.h>
#include <sys/resource.h>

#include "cfg.h"
#include "ClientConn.h"
#include "ClientCtrl.h"
#include "sockets.h"

#define MaxPacketSize 1000000

static int lsock;
static int32_t lsockpdescpos;

// from config
static char *ListenHost;
static char *ListenPort;

static uint32_t stats_prcvd = 0;
static uint32_t stats_psent = 0;
static uint64_t stats_brcvd = 0;
static uint64_t stats_bsent = 0;

void matoclserv_stats(uint64_t stats[5]) {
    stats[0] = stats_prcvd;
    stats[1] = stats_psent;
    stats[2] = stats_brcvd;
    stats[3] = stats_bsent;
    stats_prcvd = 0;
    stats_psent = 0;
    stats_brcvd = 0;
    stats_bsent = 0;
}

void matoclserv_chunk_status(uint64_t chunkid,uint8_t status) {
    uint32_t qid,inode,uid,gid,auid,agid;
    uint64_t fleng;
    uint8_t type,attr[35];
    uint32_t version;
    uint8_t *ptr;
    uint8_t count;
    uint8_t loc[100*6];
    chunklist *cl,**acl;
    CClientConn *eptr=NULL,*eaptr;

    qid=fleng=type=inode=uid=gid=auid=agid=0;

    for (eaptr = CClientConn::s_pConnHead ; eaptr && eptr==NULL ; eaptr=eaptr->next)
    {
        if (eaptr->mode!=KILL) {
            acl = &(eaptr->chunkDelayedOps);
            while (*acl && eptr==NULL) {
                cl = *acl;
                if (cl->chunkid==chunkid) {
                    eptr = eaptr;
                    qid = cl->qid;
                    fleng = cl->fleng;
                    type = cl->type;
                    inode = cl->inode;
                    uid = cl->uid;
                    gid = cl->gid;
                    auid = cl->auid;
                    agid = cl->agid;

                    *acl = cl->next;
                    free(cl);
                } else {
                    acl = &(cl->next);
                }
            }
        }
    }

    if (!eptr) {
        syslog(LOG_WARNING,"got chunk status, but don't want it");
        return;
    }
    if (status==STATUS_OK) {
        dcm_modify(inode,eptr->sesData->sessionid);
    }

    switch (type) {
    case FUSE_WRITE:
        if (status==STATUS_OK) {
            status=get_version_locations(chunkid,eptr->peerip,&version,&count,loc);
            //syslog(LOG_NOTICE,"get version for chunk %"PRIu64" -> %"PRIu32,chunkid,version);
        }
        if (status!=STATUS_OK) {
            ptr = eptr->createPacket(MATOCL_FUSE_WRITE_CHUNK,5);
            put32bit(&ptr,qid);
            put8bit(&ptr,status);
            fs_writeend(0,0,chunkid);	// ignore status - just do it.
            return;
        }
        ptr = eptr->createPacket(MATOCL_FUSE_WRITE_CHUNK,24+count*6);
        put32bit(&ptr,qid);
        put64bit(&ptr,fleng);
        put64bit(&ptr,chunkid);
        put32bit(&ptr,version);
        memcpy(ptr,loc,count*6);

        return;
    case FUSE_TRUNCATE:
        fs_end_setlength(chunkid);

        if (status!=STATUS_OK) {
            ptr = eptr->createPacket(MATOCL_FUSE_TRUNCATE,5);
            put32bit(&ptr,qid);
            put8bit(&ptr,status);
            return;
        }
        fs_do_setlength(eptr->sesData->rootinode,eptr->sesData->sesflags,inode,uid,gid,auid,agid,fleng,attr);
        ptr = eptr->createPacket(MATOCL_FUSE_TRUNCATE,39);
        put32bit(&ptr,qid);
        memcpy(ptr,attr,35);
        return;
    default:
        syslog(LOG_WARNING,"got chunk status, but operation type is unknown");
    }
}

void matoclserv_gotpacket(CClientConn *eptr,uint32_t type,const uint8_t *data,uint32_t length) {

    // for future use
    if (type==ANTOAN_NOP || type==ANTOAN_UNKNOWN_COMMAND || type==ANTOAN_BAD_COMMAND_SIZE) {
        return;
    }

    if (eptr->registered==0) {	// unregistered clients - beware that in this context sesData is NULL
        switch (type) {
        case CLTOMA_FUSE_REGISTER:
            eptr->fuse_register(data,length);
            break;
        case CLTOMA_CSERV_LIST:
            eptr->cserv_list(data,length);
            break;
        case CLTOMA_SESSION_LIST:
            eptr->session_list(data,length);
            break;
        case CLTOAN_CHART:
            eptr->serv_chart(data,length);
            break;
        case CLTOAN_CHART_DATA:
            eptr->chart_data(data,length);
            break;
        case CLTOMA_INFO:
            eptr->serv_info(data,length);
            break;
        case CLTOMA_FSTEST_INFO:
            eptr->fstest_info(data,length);
            break;
        case CLTOMA_CHUNKSTEST_INFO:
            eptr->chunkstest_info(data,length);
            break;
        case CLTOMA_CHUNKS_MATRIX:
            eptr->chunks_matrix(data,length);
            break;
        case CLTOMA_QUOTA_INFO:
            eptr->quota_info(data,length);
            break;
        case CLTOMA_EXPORTS_INFO:
            eptr->exports_info(data,length);
            break;
        case CLTOMA_MLOG_LIST:
            eptr->mlog_list(data,length);
            break;
        case CLTOMA_CSSERV_REMOVESERV:
            eptr->cserv_removeserv(data,length);
            break;
        default:
            syslog(LOG_NOTICE,"main master server module: got unknown message from unregistered (type:%"PRIu32")",type);
            eptr->mode=KILL;
        }
    } else if (eptr->registered<100) {	// mounts and new tools
        if (eptr->sesData==NULL) {
            syslog(LOG_ERR,"registered connection without sesData !!!");
            eptr->mode=KILL;
            return;
        }
        switch (type) {
        case CLTOMA_FUSE_REGISTER:
            eptr->fuse_register(data,length);
            break;
        case CLTOMA_FUSE_RESERVED_INODES:
            eptr->fuse_reserved_inodes(data,length);
            break;
        case CLTOMA_FUSE_STATFS:
            eptr->fuse_statfs(data,length);
            break;
        case CLTOMA_FUSE_ACCESS:
            eptr->fuse_access(data,length);
            break;
        case CLTOMA_FUSE_LOOKUP:
            eptr->fuse_lookup(data,length);
            break;
        case CLTOMA_FUSE_GETATTR:
            eptr->fuse_getattr(data,length);
            break;
        case CLTOMA_FUSE_SETATTR:
            eptr->fuse_setattr(data,length);
            break;
        case CLTOMA_FUSE_READLINK:
            eptr->fuse_readlink(data,length);
            break;
        case CLTOMA_FUSE_SYMLINK:
            eptr->fuse_symlink(data,length);
            break;
        case CLTOMA_FUSE_MKNOD:
            eptr->fuse_mknod(data,length);
            break;
        case CLTOMA_FUSE_MKDIR:
            eptr->fuse_mkdir(data,length);
            break;
        case CLTOMA_FUSE_UNLINK:
            eptr->fuse_unlink(data,length);
            break;
        case CLTOMA_FUSE_RMDIR:
            eptr->fuse_rmdir(data,length);
            break;
        case CLTOMA_FUSE_RENAME:
            eptr->fuse_rename(data,length);
            break;
        case CLTOMA_FUSE_LINK:
            eptr->fuse_link(data,length);
            break;
        case CLTOMA_FUSE_GETDIR:
            eptr->fuse_getdir(data,length);
            break;
        case CLTOMA_FUSE_OPEN:
            eptr->fuse_open(data,length);
            break;
        case CLTOMA_FUSE_READ_CHUNK:
            eptr->fuse_read_chunk(data,length);
            break;
        case CLTOMA_FUSE_WRITE_CHUNK:
            eptr->fuse_write_chunk(data,length);
            break;
        case CLTOMA_FUSE_WRITE_CHUNK_END:
            eptr->fuse_write_chunk_end(data,length);
            break;
            // fuse - meta
        case CLTOMA_FUSE_GETTRASH:
            eptr->fuse_gettrash(data,length);
            break;
        case CLTOMA_FUSE_GETDETACHEDATTR:
            eptr->fuse_getdetachedattr(data,length);
            break;
        case CLTOMA_FUSE_GETTRASHPATH:
            eptr->fuse_gettrashpath(data,length);
            break;
        case CLTOMA_FUSE_SETTRASHPATH:
            eptr->fuse_settrashpath(data,length);
            break;
        case CLTOMA_FUSE_UNDEL:
            eptr->fuse_undel(data,length);
            break;
        case CLTOMA_FUSE_PURGE:
            eptr->fuse_purge(data,length);
            break;
        case CLTOMA_FUSE_GETRESERVED:
            eptr->fuse_getreserved(data,length);
            break;
        case CLTOMA_FUSE_CHECK:
            eptr->fuse_check(data,length);
            break;
        case CLTOMA_FUSE_GETTRASHTIME:
            eptr->fuse_gettrashtime(data,length);
            break;
        case CLTOMA_FUSE_SETTRASHTIME:
            eptr->fuse_settrashtime(data,length);
            break;
        case CLTOMA_FUSE_GETGOAL:
            eptr->fuse_getgoal(data,length);
            break;
        case CLTOMA_FUSE_SETGOAL:
            eptr->fuse_setgoal(data,length);
            break;
        case CLTOMA_FUSE_APPEND:
            eptr->fuse_append(data,length);
            break;
        case CLTOMA_FUSE_GETDIRSTATS:
            eptr->fuse_getdirstats_old(data,length);
            break;
        case CLTOMA_FUSE_TRUNCATE:
            eptr->fuse_truncate(data,length);
            break;
        case CLTOMA_FUSE_REPAIR:
            eptr->fuse_repair(data,length);
            break;
        case CLTOMA_FUSE_SNAPSHOT:
            eptr->fuse_snapshot(data,length);
            break;
        case CLTOMA_FUSE_GETEATTR:
            eptr->fuse_geteattr(data,length);
            break;
        case CLTOMA_FUSE_SETEATTR:
            eptr->fuse_seteattr(data,length);
            break;
            /* do not use in version before 1.7.x */
        case CLTOMA_FUSE_GETXATTR:
            eptr->fuse_getxattr(data,length);
            break;
        case CLTOMA_FUSE_SETXATTR:
            eptr->fuse_setxattr(data,length);
            break;
        case CLTOMA_FUSE_QUOTACONTROL:
            eptr->fuse_quotacontrol(data,length);
            break;
            /* for tools - also should be available for registered clients */
        case CLTOMA_CSERV_LIST:
            eptr->cserv_list(data,length);
            break;
        case CLTOMA_SESSION_LIST:
            eptr->session_list(data,length);
            break;
        case CLTOAN_CHART:
            eptr->serv_chart(data,length);
            break;
        case CLTOAN_CHART_DATA:
            eptr->chart_data(data,length);
            break;
        case CLTOMA_INFO:
            eptr->serv_info(data,length);
            break;
        case CLTOMA_FSTEST_INFO:
            eptr->fstest_info(data,length);
            break;
        case CLTOMA_CHUNKSTEST_INFO:
            eptr->chunkstest_info(data,length);
            break;
        case CLTOMA_CHUNKS_MATRIX:
            eptr->chunks_matrix(data,length);
            break;
        case CLTOMA_QUOTA_INFO:
            eptr->quota_info(data,length);
            break;
        case CLTOMA_EXPORTS_INFO:
            eptr->exports_info(data,length);
            break;
        case CLTOMA_MLOG_LIST:
            eptr->mlog_list(data,length);
            break;
        case CLTOMA_CSSERV_REMOVESERV:
            eptr->cserv_removeserv(data,length);
            break;
        default:
            syslog(LOG_NOTICE,"main master server module: got unknown message from mfsmount (type:%"PRIu32")",type);
            eptr->mode=KILL;
        }
    } else {	// old mfstools
        if (eptr->sesData==NULL) {
            syslog(LOG_ERR,"registered connection (tools) without sesData !!!");
            eptr->mode=KILL;
            return;
        }

        switch (type) {
            // extra (external tools)
        case CLTOMA_FUSE_REGISTER:
            eptr->fuse_register(data,length);
            break;
        case CLTOMA_FUSE_READ_CHUNK:	// used in mfsfileinfo
            eptr->fuse_read_chunk(data,length);
            break;
        case CLTOMA_FUSE_CHECK:
            eptr->fuse_check(data,length);
            break;
        case CLTOMA_FUSE_GETTRASHTIME:
            eptr->fuse_gettrashtime(data,length);
            break;
        case CLTOMA_FUSE_SETTRASHTIME:
            eptr->fuse_settrashtime(data,length);
            break;
        case CLTOMA_FUSE_GETGOAL:
            eptr->fuse_getgoal(data,length);
            break;
        case CLTOMA_FUSE_SETGOAL:
            eptr->fuse_setgoal(data,length);
            break;
        case CLTOMA_FUSE_APPEND:
            eptr->fuse_append(data,length);
            break;
        case CLTOMA_FUSE_GETDIRSTATS:
            eptr->fuse_getdirstats(data,length);
            break;
        case CLTOMA_FUSE_TRUNCATE:
            eptr->fuse_truncate(data,length);
            break;
        case CLTOMA_FUSE_REPAIR:
            eptr->fuse_repair(data,length);
            break;
        case CLTOMA_FUSE_SNAPSHOT:
            eptr->fuse_snapshot(data,length);
            break;
        case CLTOMA_FUSE_GETEATTR:
            eptr->fuse_geteattr(data,length);
            break;
        case CLTOMA_FUSE_SETEATTR:
            eptr->fuse_seteattr(data,length);
            break;
            /* do not use in version before 1.7.x */
        case CLTOMA_FUSE_QUOTACONTROL:
            eptr->fuse_quotacontrol(data,length);
            break;
            /* ------ */
        default:
            syslog(LOG_NOTICE,"main master server module: got unknown message from mfstools (type:%"PRIu32")",type);
            eptr->mode=KILL;
        }
    }
}

void matoclserv_term(void) {
    CClientConn *eptr,*eptrn;
    packetStruct *pptr,*pptrn;
    chunklist *cl,*cln;
    STSession *ss,*ssn;
    filelist *of,*ofn;

    syslog(LOG_NOTICE,"main master server module: closing %s:%s",ListenHost,ListenPort);
    tcpClose(lsock);

    for (eptr = CClientConn::s_pConnHead ; eptr ; eptr = eptrn) {
        eptrn = eptr->next;
        if (eptr->inputpacket.packet) {
            free(eptr->inputpacket.packet);
        }
        for (pptr = eptr->outputhead ; pptr ; pptr = pptrn) {
            pptrn = pptr->next;
            if (pptr->packet) {
                free(pptr->packet);
            }
            free(pptr);
        }
        for (cl = eptr->chunkDelayedOps ; cl ; cl = cln) {
            cln = cl->next;
            free(cl);
        }
        free(eptr);
    }
    for (ss = CClientConn::s_pSessHead ; ss ; ss = ssn) {
        ssn = ss->next;
        for (of = ss->openedfiles ; of ; of = ofn) {
            ofn = of->next;
            free(of);
        }
        if (ss->info) {
            free(ss->info);
        }
        free(ss);
    }

    free(ListenHost);
    free(ListenPort);
}

void matoclserv_read(CClientConn *eptr) {
    int32_t i;
    uint32_t type,size;
    const uint8_t *ptr;

    for (;;) {
        i=read(eptr->sock,eptr->inputpacket.startptr,eptr->inputpacket.bytesleft);
        if (i==0) {
            if (eptr->registered>0 && eptr->registered<100) {	// show this message only for standard, registered clients
                syslog(LOG_NOTICE,"connection with client(ip:%u.%u.%u.%u) has been closed by peer",(eptr->peerip>>24)&0xFF,(eptr->peerip>>16)&0xFF,(eptr->peerip>>8)&0xFF,eptr->peerip&0xFF);
            }
            eptr->mode = KILL;
            return;
        }
        if (i<0) {
            if (errno!=EAGAIN) {
#ifdef ECONNRESET
                if (errno!=ECONNRESET || eptr->registered<100) {
#endif
                    mfs_arg_errlog_silent(LOG_NOTICE,"main master server module: (ip:%u.%u.%u.%u) read error",(eptr->peerip>>24)&0xFF,(eptr->peerip>>16)&0xFF,(eptr->peerip>>8)&0xFF,eptr->peerip&0xFF);
#ifdef ECONNRESET
                }
#endif
                eptr->mode = KILL;
            }
            return;
        }
        eptr->inputpacket.startptr+=i;
        eptr->inputpacket.bytesleft-=i;
        stats_brcvd+=i;

        if (eptr->inputpacket.bytesleft>0) {
            return;
        }

        if (eptr->mode==HEADER) {
            ptr = eptr->hdrbuff+4;
            size = get32bit(&ptr);

            if (size>0) {
                if (size>MaxPacketSize) {
                    syslog(LOG_WARNING,"main master server module: packet too long (%"PRIu32"/%u)",size,MaxPacketSize);
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

            matoclserv_gotpacket(eptr,type,eptr->inputpacket.packet,size);
            stats_prcvd++;

            if (eptr->inputpacket.packet) {
                free(eptr->inputpacket.packet);
            }
            eptr->inputpacket.packet=NULL;
        }
    }
}

void matoclserv_write(CClientConn *eptr) {
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
                mfs_arg_errlog_silent(LOG_NOTICE,"main master server module: (ip:%u.%u.%u.%u) write error",(eptr->peerip>>24)&0xFF,(eptr->peerip>>16)&0xFF,(eptr->peerip>>8)&0xFF,eptr->peerip&0xFF);
                eptr->mode = KILL;
            }
            return;
        }
        pack->startptr+=i;
        pack->bytesleft-=i;
        stats_bsent+=i;
        if (pack->bytesleft>0) {
            return;
        }
        free(pack->packet);
        stats_psent++;
        eptr->outputhead = pack->next;
        if (eptr->outputhead==NULL) {
            eptr->outputtail = &(eptr->outputhead);
        }
        free(pack);
    }
}

void matoclserv_wantexit(void) {
    CClientConn::s_exiting = 1;
}

int matoclserv_canexit(void) {
    CClientConn *eptr;
    for (eptr=CClientConn::s_pConnHead ; eptr ; eptr=eptr->next) {
        if (eptr->outputhead!=NULL) {
            return 0;
        }
        if (eptr->chunkDelayedOps!=NULL) {
            return 0;
        }
    }
    return 1;
}

void matoclserv_desc(struct pollfd *pdesc,uint32_t *ndesc) {
    uint32_t pos = *ndesc;
    CClientConn *eptr;

    if (CClientConn::s_exiting==0) {
        pdesc[pos].fd = lsock;
        pdesc[pos].events = POLLIN;
        lsockpdescpos = pos;
        pos++;
    } else {
        lsockpdescpos = -1;
    }

    for (eptr=CClientConn::s_pConnHead ; eptr ; eptr=eptr->next) {
        pdesc[pos].fd = eptr->sock;
        pdesc[pos].events = 0;
        eptr->pdescpos = pos;
        if (CClientConn::s_exiting==0) {
            pdesc[pos].events |= POLLIN;
        }
        if (eptr->outputhead!=NULL) {
            pdesc[pos].events |= POLLOUT;
        }
        pos++;
    }
    *ndesc = pos;
}


void matoclserv_serve(struct pollfd *pdesc) {
    uint32_t now=CServerCore::get_time();
    CClientConn *eptr,**kptr;
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
            mfs_errlog_silent(LOG_NOTICE,"main master server module: accept error");
        } else {
            tcpNonBlock(ns);
            tcpNoDelay(ns);
            eptr = (CClientConn*)malloc(sizeof(CClientConn));
            passert(eptr);
            eptr->next = CClientConn::s_pConnHead;
            CClientConn::s_pConnHead = eptr;

            eptr->init(ns, now);
            tcpGetPeer(ns,&(eptr->peerip),NULL);
            eptr->registered = 0;
            eptr->version = 0;
            eptr->mode = HEADER;
            eptr->chunkDelayedOps = NULL;
            eptr->sesData = NULL;
            memset(eptr->passwordrnd,0,32);
        }
    }

    // read
    for (eptr=CClientConn::s_pConnHead ; eptr ; eptr=eptr->next) {
        if (eptr->pdescpos>=0) {
            if (pdesc[eptr->pdescpos].revents & (POLLERR|POLLHUP)) {
                eptr->mode = KILL;
            }
            if ((pdesc[eptr->pdescpos].revents & POLLIN) && eptr->mode!=KILL) {
                eptr->lastread = now;
                matoclserv_read(eptr);
            }
        }
    }

    // timeout fix
    unow = CServerCore::get_precise_utime();
    timeoutadd = (unow-lastaction)/1000000;
    if (timeoutadd) {
        for (eptr=CClientConn::s_pConnHead ; eptr ; eptr=eptr->next) {
            eptr->lastread += timeoutadd;
        }
    }
    lastaction = unow;

    // write
    for (eptr=CClientConn::s_pConnHead ; eptr ; eptr=eptr->next) {
        if (eptr->lastwrite+2<now && eptr->registered<100 && eptr->outputhead==NULL) {
            uint8_t *ptr = eptr->createPacket(ANTOAN_NOP,4);	// 4 byte length because of 'msgid'
            *((uint32_t*)ptr) = 0;
        }
        if (eptr->pdescpos>=0) {
            if ((((pdesc[eptr->pdescpos].events & POLLOUT)==0 && (eptr->outputhead))
                || (pdesc[eptr->pdescpos].revents & POLLOUT)) && eptr->mode!=KILL) {
                    eptr->lastwrite = now;
                    matoclserv_write(eptr);
            }
        }
        if (eptr->lastread+10<now && CClientConn::s_exiting==0) {
            eptr->mode = KILL;
        }
    }

    // close
    kptr = &CClientConn::s_pConnHead;
    while ((eptr=*kptr)) {
        if (eptr->mode == KILL) {
            eptr->before_disconnect();
            tcpClose(eptr->sock);
            eptr->clear();

            *kptr = eptr->next;
            free(eptr);
        } else {
            kptr = &(eptr->next);
        }
    }
}

void matoclserv_start_cond_check(void) {
    if (CClientConn::s_starting) {
        // very simple condition checking if all chunkservers have been connected
        // in the future master will know his chunkservers list and then this condition will be changed
        if (CFileSysMgr::get_chunks_missing_count()<100) {
            CClientConn::s_starting=0;
        } else {
            CClientConn::s_starting--;
        }
    }
}

int matoclserv_sessionsinit(void) {
    fprintf(stderr,"loading sessions ... ");
    fflush(stderr);
    CClientConn::s_pSessHead = NULL;
    switch (CClientConn::load_sessions()) {
    case 0:	// no file
        fprintf(stderr,"file not found\n");
        fprintf(stderr,"if it is not fresh installation then you have to restart all active mounts !!!\n");
        CClientConn::store_sessions();
        break;
    case 1: // file loaded
        fprintf(stderr,"ok\n");
        fprintf(stderr,"sessions file has been loaded\n");
        break;
    default:
        fprintf(stderr,"error\n");
        fprintf(stderr,"due to missing sessions you have to restart all active mounts !!!\n");
        break;
    }

    CClientConn::s_SessSustainTime = cfg_getuint32("SESSION_SUSTAIN_TIME",86400);
    if (CClientConn::s_SessSustainTime>7*86400) {
        CClientConn::s_SessSustainTime=7*86400;
        mfs_syslog(LOG_WARNING,"SESSION_SUSTAIN_TIME too big (more than week) - setting this value to one week");
    }

    if (CClientConn::s_SessSustainTime<60) {
        CClientConn::s_SessSustainTime=60;
        mfs_syslog(LOG_WARNING,"SESSION_SUSTAIN_TIME too low (less than minute) - setting this value to one minute");
    }

    return 0;
}

void matoclserv_reload(void) {
    char *oldListenHost,*oldListenPort;
    int newlsock;

    CClientConn::s_RejectOld = cfg_getuint32("REJECT_OLD_CLIENTS",0);
    CClientConn::s_SessSustainTime = cfg_getuint32("SESSION_SUSTAIN_TIME",86400);
    if (CClientConn::s_SessSustainTime>7*86400) {
        CClientConn::s_SessSustainTime=7*86400;
        mfs_syslog(LOG_WARNING,"SESSION_SUSTAIN_TIME too big (more than week) - setting this value to one week");
    }

    if (CClientConn::s_SessSustainTime<60) {
        CClientConn::s_SessSustainTime=60;
        mfs_syslog(LOG_WARNING,"SESSION_SUSTAIN_TIME too low (less than minute) - setting this value to one minute");
    }

    oldListenHost = ListenHost;
    oldListenPort = ListenPort;
    if (cfg_isdefined("MATOCL_LISTEN_HOST") || cfg_isdefined("MATOCL_LISTEN_PORT") || !(cfg_isdefined("MATOCU_LISTEN_HOST") || cfg_isdefined("MATOCU_LISTEN_HOST"))) {
        ListenHost = cfg_getstr("MATOCL_LISTEN_HOST","*");
        ListenPort = cfg_getstr("MATOCL_LISTEN_PORT","9421");
    } else {
        ListenHost = cfg_getstr("MATOCU_LISTEN_HOST","*");
        ListenPort = cfg_getstr("MATOCU_LISTEN_PORT","9421");
    }

    if (strcmp(oldListenHost,ListenHost)==0 && strcmp(oldListenPort,ListenPort)==0) {
        free(oldListenHost);
        free(oldListenPort);
        mfs_arg_syslog(LOG_NOTICE,"main master server module: socket address hasn't changed (%s:%s)",ListenHost,ListenPort);
        return;
    }

    newlsock = tcpSocket();
    if (newlsock<0) {
        mfs_errlog(LOG_WARNING,"main master server module: socket address has changed, but can't create new socket");
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
        mfs_errlog_silent(LOG_NOTICE,"main master server module: can't set accept filter");
    }
    if (tcpStrListen(newlsock,ListenHost,ListenPort,100)<0) {
        mfs_arg_errlog(LOG_ERR,"main master server module: socket address has changed, but can't listen on socket (%s:%s)",ListenHost,ListenPort);
        free(ListenHost);
        free(ListenPort);
        ListenHost = oldListenHost;
        ListenPort = oldListenPort;
        tcpClose(newlsock);
        return;
    }
    mfs_arg_syslog(LOG_NOTICE,"main master server module: socket address has changed, now listen on %s:%s",ListenHost,ListenPort);
    free(oldListenHost);
    free(oldListenPort);
    tcpClose(lsock);
    lsock = newlsock;
}

int matoclserv_networkinit(void)
{
    if (cfg_isdefined("MATOCL_LISTEN_HOST") 
        || cfg_isdefined("MATOCL_LISTEN_PORT") 
        || !(cfg_isdefined("MATOCU_LISTEN_HOST")
        || cfg_isdefined("MATOCU_LISTEN_HOST")))
    {
        ListenHost = cfg_getstr("MATOCL_LISTEN_HOST","*");
        ListenPort = cfg_getstr("MATOCL_LISTEN_PORT","9421");
    } else {
        fprintf(stderr,"change MATOCU_LISTEN_* option names to MATOCL_LISTEN_* !!!\n");
        ListenHost = cfg_getstr("MATOCU_LISTEN_HOST","*");
        ListenPort = cfg_getstr("MATOCU_LISTEN_PORT","9421");
    }
    CClientConn::s_RejectOld = cfg_getuint32("REJECT_OLD_CLIENTS",0);

    CClientConn::s_exiting = 0;
    CClientConn::s_starting = 12;
    lsock = tcpSocket();
    if (lsock<0) {
        mfs_errlog(LOG_ERR,"main master server module: can't create socket");
        return -1;
    }
    tcpNonBlock(lsock);
    tcpNoDelay(lsock);
    tcpReuseAddr(lsock);
    if (tcpSetAcceptFilter(lsock)<0 && errno!=ENOTSUP) {
        mfs_errlog_silent(LOG_NOTICE,"main master server module: can't set accept filter");
    }
    if (tcpStrListen(lsock,ListenHost,ListenPort,100)<0) {
        mfs_arg_errlog(LOG_ERR,"main master server module: can't listen on %s:%s",ListenHost,ListenPort);
        return -1;
    }
    mfs_arg_syslog(LOG_NOTICE,"main master server module: listen on %s:%s",ListenHost,ListenPort);

    CClientConn::s_pConnHead = NULL;

    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,10,0,matoclserv_start_cond_check);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,10,0, CClientConn::session_check);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,3600,0, CClientConn::session_statsmove);
    CServerCore::getInstance()->reload_register(matoclserv_reload);
    CServerCore::getInstance()->destruct_register(matoclserv_term);
    CServerCore::getInstance()->poll_register(matoclserv_desc,matoclserv_serve);
    CServerCore::getInstance()->wantexit_register(matoclserv_wantexit);
    CServerCore::getInstance()->canexit_register(matoclserv_canexit);

    return 0;
}
