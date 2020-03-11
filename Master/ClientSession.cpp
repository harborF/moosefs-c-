#include "ClientConn.h"
#include "FileSysMgr.h"
#include "FileIDMgr.h"

void CClientConn::session_list(const uint8_t *data,uint32_t length)
{

    if (length!=0 && length!=1) {
        syslog(LOG_NOTICE,"CLTOMA_SESSION_LIST - wrong size (%"PRIu32"/0)", length);
        this->mode = KILL;
        return;
    }

    uint8_t vmode = length==0 ? 0 : get8bit(&data);

    CClientConn *eaptr;
    uint32_t size = 2,ileng,pleng,i;
    for (eaptr = s_pConnHead; eaptr ; eaptr=eaptr->next)
    {
        if (eaptr->mode!=KILL && eaptr->sesData && eaptr->registered>0 && eaptr->registered<100)
        {
            size += 37+SESSION_STATS*8+(vmode?10:0);
            if (eaptr->sesData->info) {
                size += strlen(eaptr->sesData->info);
            }

            if (eaptr->sesData->rootinode==0) {
                size += 1;
            } else {
                size += CFsNode::getdirpath_size(eaptr->sesData->rootinode);
            }
        }
    }

    uint8_t *ptr = this->createPacket(MATOCL_SESSION_LIST,size);
    put16bit(&ptr, SESSION_STATS);

    for (eaptr = s_pConnHead ; eaptr ; eaptr=eaptr->next)
    {
        if (eaptr->mode!=KILL && eaptr->sesData && eaptr->registered>0 && eaptr->registered<100)
        {
            put32bit(&ptr,eaptr->sesData->sessionid);
            put32bit(&ptr,eaptr->peerip);
            put32bit(&ptr,eaptr->version);

            if (eaptr->sesData->info) {
                ileng = strlen(eaptr->sesData->info);
                put32bit(&ptr,ileng);
                memcpy(ptr,eaptr->sesData->info,ileng);
                ptr+=ileng;
            } else {
                put32bit(&ptr,0);
            }

            if (eaptr->sesData->rootinode==0) {
                put32bit(&ptr,1);
                put8bit(&ptr,'.');
            } else {
                pleng = CFsNode::getdirpath_size(eaptr->sesData->rootinode);
                put32bit(&ptr,pleng);
                if (pleng>0) {
                    CFsNode::getdirpath_data(eaptr->sesData->rootinode,ptr,pleng);
                    ptr+=pleng;
                }
            }

            put8bit(&ptr,eaptr->sesData->sesflags);
            put32bit(&ptr,eaptr->sesData->rootuid);
            put32bit(&ptr,eaptr->sesData->rootgid);
            put32bit(&ptr,eaptr->sesData->mapalluid);
            put32bit(&ptr,eaptr->sesData->mapallgid);

            if (vmode) {
                put8bit(&ptr,eaptr->sesData->mingoal);
                put8bit(&ptr,eaptr->sesData->maxgoal);
                put32bit(&ptr,eaptr->sesData->mintrashtime);
                put32bit(&ptr,eaptr->sesData->maxtrashtime);
            }

            if (eaptr->sesData) {
                for (i=0 ; i<SESSION_STATS ; i++) {
                    put32bit(&ptr,eaptr->sesData->curOpStats[i]);
                }
                for (i=0 ; i<SESSION_STATS ; i++) {
                    put32bit(&ptr,eaptr->sesData->lastHourOpStats[i]);
                }
            } else {
                memset(ptr,0xFF,8*SESSION_STATS);
                ptr+=8*SESSION_STATS;
            }
        }//end if
    }//end for
}

void CClientConn::store_sessions()
{
    FILE *fd = fopen("sessions.mfs.tmp","w");
    if (fd==NULL) {
        mfs_errlog_silent(LOG_WARNING,"can't store sessions, open error");
        return;
    }

    uint8_t fsesrecord[43+SESSION_STATS*8];	// 4+4+4+4+1+1+1+4+4+4+4+4+4+SESSION_STATS*4+SESSION_STATS*4
    memcpy(fsesrecord,MFSSIGNATURE "S \001\006\004",8);
    uint8_t *ptr = fsesrecord+8;
    put16bit(&ptr,SESSION_STATS);
    if (fwrite(fsesrecord,10,1,fd)!=1) {
        syslog(LOG_WARNING,"can't store sessions, fwrite error");
        fclose(fd);
        return;
    }

    uint32_t ileng;
    int i;
    for (STSession *asesdata = s_pSessHead; asesdata ; asesdata=asesdata->next) {
        if (asesdata->newsession==1) {
            ptr = fsesrecord;
            if (asesdata->info) {
                ileng = strlen(asesdata->info);
            } else {
                ileng = 0;
            }

            put32bit(&ptr,asesdata->sessionid);
            put32bit(&ptr,ileng);
            put32bit(&ptr,asesdata->peerip);
            put32bit(&ptr,asesdata->rootinode);
            put8bit(&ptr,asesdata->sesflags);
            put8bit(&ptr,asesdata->mingoal);
            put8bit(&ptr,asesdata->maxgoal);
            put32bit(&ptr,asesdata->mintrashtime);
            put32bit(&ptr,asesdata->maxtrashtime);
            put32bit(&ptr,asesdata->rootuid);
            put32bit(&ptr,asesdata->rootgid);
            put32bit(&ptr,asesdata->mapalluid);
            put32bit(&ptr,asesdata->mapallgid);

            for (i=0 ; i<SESSION_STATS ; i++) {
                put32bit(&ptr,asesdata->curOpStats[i]);
            }

            for (i=0 ; i<SESSION_STATS ; i++) {
                put32bit(&ptr,asesdata->lastHourOpStats[i]);
            }

            if (fwrite(fsesrecord,(43+SESSION_STATS*8),1,fd)!=1) {
                syslog(LOG_WARNING,"can't store sessions, fwrite error");
                fclose(fd);
                return;
            }

            if (ileng>0) {
                if (fwrite(asesdata->info,ileng,1,fd)!=1) {
                    syslog(LOG_WARNING,"can't store sessions, fwrite error");
                    fclose(fd);
                    return;
                }
            }
        }
    }

    if (fclose(fd)!=0) {
        mfs_errlog_silent(LOG_WARNING,"can't store sessions, fclose error");
        return;
    }

    if (rename("sessions.mfs.tmp","sessions.mfs")<0) {
        mfs_errlog_silent(LOG_WARNING,"can't store sessions, rename error");
    }
}

int CClientConn::load_sessions()
{
    FILE *fd = fopen("sessions.mfs","r");
    if (fd==NULL) {
        mfs_errlog_silent(LOG_WARNING,"can't load sessions, fopen error");
        if (errno==ENOENT) {	// it's ok if file does not exist
            return 0;
        } else {
            return -1;
        }
    }

    uint8_t hdr[8];
    if (fread(hdr,8,1,fd)!=1) {
        syslog(LOG_WARNING,"can't load sessions, fread error");
        fclose(fd);
        return -1;
    }

    STSession *asesdata;
    uint32_t ileng;
    uint8_t *fsesrecord;
    const uint8_t *ptr;
    uint8_t mapalldata,goaltrashdata;
    uint32_t i,statsinfile;
    int r;

    if (memcmp(hdr,MFSSIGNATURE "S 1.5",8)==0) {
        mapalldata = 0;
        goaltrashdata = 0;
        statsinfile = 16;
    } else if (memcmp(hdr,MFSSIGNATURE "S \001\006\001",8)==0) {
        mapalldata = 1;
        goaltrashdata = 0;
        statsinfile = 16;
    } else if (memcmp(hdr,MFSSIGNATURE "S \001\006\002",8)==0) {
        mapalldata = 1;
        goaltrashdata = 0;
        statsinfile = 21;
    } else if (memcmp(hdr,MFSSIGNATURE "S \001\006\003",8)==0) {
        mapalldata = 1;
        goaltrashdata = 0;
        if (fread(hdr,2,1,fd)!=1) {
            syslog(LOG_WARNING,"can't load sessions, fread error");
            fclose(fd);
            return -1;
        }
        ptr = hdr;
        statsinfile = get16bit(&ptr);
    } else if (memcmp(hdr,MFSSIGNATURE "S \001\006\004",8)==0) {
        mapalldata = 1;
        goaltrashdata = 1;
        if (fread(hdr,2,1,fd)!=1) {
            syslog(LOG_WARNING,"can't load sessions, fread error");
            fclose(fd);
            return -1;
        }
        ptr = hdr;
        statsinfile = get16bit(&ptr);
    } else {
        syslog(LOG_WARNING,"can't load sessions, bad header");
        fclose(fd);
        return -1;
    }

    if (mapalldata==0) {
        fsesrecord = (uint8_t*)malloc(25+statsinfile*8);
    } else if (goaltrashdata==0) {
        fsesrecord = (uint8_t*)malloc(33+statsinfile*8);
    } else {
        fsesrecord = (uint8_t*)malloc(43+statsinfile*8);
    }
    passert(fsesrecord);

    while (!feof(fd)) {
        if (mapalldata==0) {
            r = fread(fsesrecord,25+statsinfile*8,1,fd);
        } else if (goaltrashdata==0) {
            r = fread(fsesrecord,33+statsinfile*8,1,fd);
        } else {
            r = fread(fsesrecord,43+statsinfile*8,1,fd);
        }

        if (r==1) {
            ptr = fsesrecord;
            asesdata = (STSession*)malloc(sizeof(STSession));
            passert(asesdata);
            asesdata->sessionid = get32bit(&ptr);
            ileng = get32bit(&ptr);
            asesdata->peerip = get32bit(&ptr);
            asesdata->rootinode = get32bit(&ptr);
            asesdata->sesflags = get8bit(&ptr);

            if (goaltrashdata) {
                asesdata->mingoal = get8bit(&ptr);
                asesdata->maxgoal = get8bit(&ptr);
                asesdata->mintrashtime = get32bit(&ptr);
                asesdata->maxtrashtime = get32bit(&ptr);
            } else { // set defaults (no limits)
                asesdata->mingoal = 1;
                asesdata->maxgoal = 9;
                asesdata->mintrashtime = 0;
                asesdata->maxtrashtime = UINT32_C(0xFFFFFFFF);
            }

            asesdata->rootuid = get32bit(&ptr);
            asesdata->rootgid = get32bit(&ptr);
            if (mapalldata) {
                asesdata->mapalluid = get32bit(&ptr);
                asesdata->mapallgid = get32bit(&ptr);
            } else {
                asesdata->mapalluid = 0;
                asesdata->mapallgid = 0;
            }

            asesdata->info = NULL;
            asesdata->newsession = 1;
            asesdata->openedfiles = NULL;
            asesdata->disconnected = CServerCore::get_time();
            asesdata->nsocks = 0;

            for (i=0 ; i<SESSION_STATS ; i++) {
                asesdata->curOpStats[i] = (i<statsinfile)?get32bit(&ptr):0;
            }
            if (statsinfile>SESSION_STATS) {
                ptr+=4*(statsinfile-SESSION_STATS);
            }
            for (i=0 ; i<SESSION_STATS ; i++) {
                asesdata->lastHourOpStats[i] = (i<statsinfile)?get32bit(&ptr):0;
            }

            if (ileng>0) {
                asesdata->info = (char*)malloc(ileng+1);
                passert(asesdata->info);
                if (fread(asesdata->info,ileng,1,fd)!=1) {
                    free(asesdata->info);
                    free(asesdata);
                    free(fsesrecord);
                    syslog(LOG_WARNING,"can't load sessions, fread error");
                    fclose(fd);
                    return -1;
                }
                asesdata->info[ileng]=0;
            }

            asesdata->next = s_pSessHead;
            s_pSessHead = asesdata;
        }

        if (ferror(fd)) {
            free(fsesrecord);
            syslog(LOG_WARNING,"can't load sessions, fread error");
            fclose(fd);
            return -1;
        }
    }

    free(fsesrecord);
    syslog(LOG_NOTICE,"sessions have been loaded");
    fclose(fd);

    return 1;
}

void CClientConn::session_statsmove(void)
{
    for (STSession *sesdata = CClientConn::s_pSessHead ; sesdata ; sesdata=sesdata->next) {
        memcpy(sesdata->lastHourOpStats,sesdata->curOpStats,4*SESSION_STATS);
        memset(sesdata->curOpStats,0,4*SESSION_STATS);
    }

    store_sessions();
}

static void session_timedout(STSession *sesdata) 
{
    filelist *fl,*afl;
    fl=sesdata->openedfiles;
    while (fl) {
        afl = fl;
        fl=fl->next;
        fs_release(afl->inode,sesdata->sessionid);
        free(afl);
    }
    sesdata->openedfiles=NULL;
    if (sesdata->info) {
        free(sesdata->info);
    }
}

void CClientConn::session_check(void)
{
    STSession **sesdata,*asesdata;
    uint32_t now = CServerCore::get_time();

    sesdata = &(s_pSessHead);
    while ((asesdata=*sesdata))
    {
        if (asesdata->nsocks==0 
            && ((asesdata->newsession>1 && asesdata->disconnected<now) 
            || (asesdata->newsession==1 && asesdata->disconnected+s_SessSustainTime<now) 
            || (asesdata->newsession==0 && asesdata->disconnected+7200<now)))
        {
                session_timedout(asesdata);
                *sesdata = asesdata->next;
                free(asesdata);
        } else {
            sesdata = &(asesdata->next);
        }
    }
}


STSession* CClientConn::new_session(uint8_t newsession,uint8_t nonewid)
{
    STSession *asesdata = (STSession*)malloc(sizeof(STSession));
    passert(asesdata);
    if (newsession==0 && nonewid) {
        asesdata->sessionid = 0;
    } else {
        asesdata->sessionid = CFileIDMgr::newSessionID();
    }

    asesdata->info = NULL;
    asesdata->peerip = 0;
    asesdata->sesflags = 0;
    asesdata->rootuid = 0;
    asesdata->rootgid = 0;
    asesdata->mapalluid = 0;
    asesdata->mapallgid = 0;
    asesdata->newsession = newsession;
    asesdata->rootinode = MFS_ROOT_ID;
    asesdata->openedfiles = NULL;
    asesdata->disconnected = 0;
    asesdata->nsocks = 1;
    memset(asesdata->curOpStats,0,4*SESSION_STATS);
    memset(asesdata->lastHourOpStats,0,4*SESSION_STATS);

    asesdata->next = s_pSessHead;
    s_pSessHead = asesdata;

    return asesdata;
}

STSession* CClientConn::find_session(uint32_t sessionid)
{
    if (sessionid==0) {
        return NULL;
    }

    for (STSession *asesdata = s_pSessHead ; asesdata ; asesdata=asesdata->next) 
    {
        if (asesdata->sessionid==sessionid) {
            if (asesdata->newsession>=2) {
                asesdata->newsession-=2;
            }
            asesdata->nsocks++;
            asesdata->disconnected = 0;
            return asesdata;
        }
    }

    return NULL;
}

void CClientConn::close_session(uint32_t sessionid)
{
    if (sessionid==0) {
        return;
    }

    for (STSession *asesdata = s_pSessHead ; asesdata ; asesdata=asesdata->next) {
        if (asesdata->sessionid==sessionid) {
            if (asesdata->nsocks==1 && asesdata->newsession<2) {
                asesdata->newsession+=2;
            }
        }
    }
    return;
}

void CClientConn::init_sessions(uint32_t sessionid,uint32_t inode)
{
    STSession *asesdata;
    for (asesdata = s_pSessHead ; asesdata && asesdata->sessionid!=sessionid; asesdata=asesdata->next) ;
 
    if (asesdata==NULL) {
        asesdata = (STSession*)malloc(sizeof(STSession));
        passert(asesdata);
        asesdata->sessionid = sessionid;
        /* STSession created by filesystem - only for old clients (pre 1.5.13) */
        asesdata->info = NULL;
        asesdata->peerip = 0;
        asesdata->sesflags = 0;
        asesdata->mingoal = 1;
        asesdata->maxgoal = 9;
        asesdata->mintrashtime = 0;
        asesdata->maxtrashtime = UINT32_C(0xFFFFFFFF);
        asesdata->rootuid = 0;
        asesdata->rootgid = 0;
        asesdata->mapalluid = 0;
        asesdata->mapallgid = 0;
        asesdata->newsession = 0;
        asesdata->rootinode = MFS_ROOT_ID;
        asesdata->openedfiles = NULL;
        asesdata->disconnected = CServerCore::get_time();
        asesdata->nsocks = 0;
        memset(asesdata->curOpStats,0,4*SESSION_STATS);
        memset(asesdata->lastHourOpStats,0,4*SESSION_STATS);

        asesdata->next = s_pSessHead;
        s_pSessHead = asesdata;
    }

    filelist *ofptr,**ofpptr;
    ofpptr = &(asesdata->openedfiles);
    while ((ofptr=*ofpptr)) {
        if (ofptr->inode==inode) {
            return;
        }
        if (ofptr->inode>inode) {
            break;
        }
        ofpptr = &(ofptr->next);
    }
    ofptr = (filelist*)malloc(sizeof(filelist));
    passert(ofptr);
    ofptr->inode = inode;
    ofptr->next = *ofpptr;
    *ofpptr = ofptr;
}
