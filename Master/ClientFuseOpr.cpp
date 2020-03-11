#include "ClientConn.h"
#include "FileSysMgr.h"

void CClientConn::fuse_register(const uint8_t *data,uint32_t length)
{
    const uint8_t *rptr;
    uint8_t *wptr;
    uint32_t sessionid;
    uint8_t status;
    uint8_t tools;

    if (s_starting) {
        this->mode = KILL;
        return;
    }

    if (length<64) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER - wrong size (%"PRIu32"/<64)",length);
        this->mode = KILL;
        return;
    }

    tools = (memcmp(data,FUSE_REGISTER_BLOB_TOOLS_NOACL,64)==0)?1:0;
    if (this->registered==0 && (memcmp(data,FUSE_REGISTER_BLOB_NOACL,64)==0 || tools)) {
        if (s_RejectOld) {
            syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/NOACL - rejected (option REJECT_OLD_CLIENTS is set)");
            this->mode = KILL;
            return;
        }
        if (tools) {
            if (length!=64 && length!=68) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/NOACL-TOOLS - wrong size (%"PRIu32"/64|68)",length);
                this->mode = KILL;
                return;
            }
        } else {
            if (length!=68 && length!=72) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/NOACL-MOUNT - wrong size (%"PRIu32"/68|72)",length);
                this->mode = KILL;
                return;
            }
        }
        rptr = data+64;
        if (tools) {
            sessionid = 0;
            if (length==68) {
                this->version = get32bit(&rptr);
            }
        } else {
            sessionid = get32bit(&rptr);
            if (length==72) {
                this->version = get32bit(&rptr);
            }
        }
        if (this->version<0x010500 && !tools) {
            syslog(LOG_NOTICE,"got register packet from mount older than 1.5 - rejecting");
            this->mode = KILL;
            return;
        }
        if (sessionid==0) {	// new STSession
            status = STATUS_OK; 
            this->sesData = CClientConn::new_session(0,tools);
            if (this->sesData==NULL) {
                syslog(LOG_NOTICE,"can't allocate STSession record");
                this->mode = KILL;
                return;
            }
            this->sesData->rootinode = MFS_ROOT_ID;
            this->sesData->sesflags = 0;
            this->sesData->peerip = this->peerip;
        } else { // reconnect or tools
            this->sesData = find_session(sessionid);
            if (this->sesData==NULL) {	// in old model if session doesn't exist then create it
                this->sesData = new_session(0,0);
                if (this->sesData==NULL) {
                    syslog(LOG_NOTICE,"can't allocate session record");
                    this->mode = KILL;
                    return;
                }
                this->sesData->rootinode = MFS_ROOT_ID;
                this->sesData->sesflags = 0;
                this->sesData->peerip = this->peerip;
                status = STATUS_OK;
            } else if (this->sesData->peerip==0) { // created by "filesystem"
                this->sesData->peerip = this->peerip;
                status = STATUS_OK;
            } else if (this->sesData->peerip==this->peerip) {
                status = STATUS_OK;
            } else {
                status = ERROR_EACCES;
            }
        }
        if (tools) {
            wptr = this->createPacket(MATOCL_FUSE_REGISTER,1);
        } else {
            wptr = this->createPacket(MATOCL_FUSE_REGISTER,(status!=STATUS_OK)?1:4);
        }
        if (status!=STATUS_OK) {
            put8bit(&wptr,status);
            return;
        }
        if (tools) {
            put8bit(&wptr,status);
        } else {
            sessionid = this->sesData->sessionid;
            put32bit(&wptr,sessionid);
        }
        this->registered = (tools)?100:1;
        return;
    } else if (memcmp(data,FUSE_REGISTER_BLOB_ACL,64)==0) {
        uint32_t rootinode;
        uint8_t sesflags;
        uint8_t mingoal,maxgoal;
        uint32_t mintrashtime,maxtrashtime;
        uint32_t rootuid,rootgid;
        uint32_t mapalluid,mapallgid;
        uint32_t ileng,pleng;
        uint8_t i,rcode;
        const uint8_t *path;
        const char *info;

        if (length<65) {
            syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL - wrong size (%"PRIu32"/<65)",length);
            this->mode = KILL;
            return;
        }

        rptr = data+64;
        rcode = get8bit(&rptr);

        if ((this->registered==0 && rcode==REGISTER_CLOSESESSION) || (this->registered && rcode!=REGISTER_CLOSESESSION)) {
            syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL - wrong rcode (%d) for registered status (%d)",rcode,this->registered);
            this->mode = KILL;
            return;
        }

        switch (rcode) {
        case REGISTER_GETRANDOM:
            if (length!=65) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.1 - wrong size (%"PRIu32"/65)",length);
                this->mode = KILL;
                return;
            }
            wptr = this->createPacket(MATOCL_FUSE_REGISTER,32);
            for (i=0 ; i<32 ; i++) {
                this->passwordrnd[i]=rndu8();
            }
            memcpy(wptr,this->passwordrnd,32);
            return;
        case REGISTER_NEWSESSION:
            if (length<77) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.2 - wrong size (%"PRIu32"/>=77)",length);
                this->mode = KILL;
                return;
            }
            this->version = get32bit(&rptr);
            ileng = get32bit(&rptr);
            if (length<77+ileng) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.2 - wrong size (%"PRIu32"/>=77+ileng(%"PRIu32"))",length,ileng);
                this->mode = KILL;
                return;
            }
            info = (const char*)rptr;
            rptr+=ileng;
            pleng = get32bit(&rptr);
            if (length!=77+ileng+pleng && length!=77+16+ileng+pleng) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.2 - wrong size (%"PRIu32"/77+ileng(%"PRIu32")+pleng(%"PRIu32")[+16])",length,ileng,pleng);
                this->mode = KILL;
                return;
            }
            path = rptr;
            rptr+=pleng;
            if (pleng>0 && rptr[-1]!=0) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.2 - received path without ending zero");
                this->mode = KILL;
                return;
            }
            if (pleng==0) {
                path = (const uint8_t*)"";
            }
            if (length==77+16+ileng+pleng) {
                status = exports_check(this->peerip,this->version,0,path,this->passwordrnd,rptr,&sesflags,&rootuid,&rootgid,&mapalluid,&mapallgid,&mingoal,&maxgoal,&mintrashtime,&maxtrashtime);
            } else {
                status = exports_check(this->peerip,this->version,0,path,NULL,NULL,&sesflags,&rootuid,&rootgid,&mapalluid,&mapallgid,&mingoal,&maxgoal,&mintrashtime,&maxtrashtime);
            }
            if (status==STATUS_OK) {
                status = fs_getrootinode(&rootinode,path);
            }
            if (status==STATUS_OK) {
                this->sesData = CClientConn::new_session(1,0);
                if (this->sesData==NULL) {
                    syslog(LOG_NOTICE,"can't allocate session record");
                    this->mode = KILL;
                    return;
                }
                this->sesData->rootinode = rootinode;
                this->sesData->sesflags = sesflags;
                this->sesData->rootuid = rootuid;
                this->sesData->rootgid = rootgid;
                this->sesData->mapalluid = mapalluid;
                this->sesData->mapallgid = mapallgid;
                this->sesData->mingoal = mingoal;
                this->sesData->maxgoal = maxgoal;
                this->sesData->mintrashtime = mintrashtime;
                this->sesData->maxtrashtime = maxtrashtime;
                this->sesData->peerip = this->peerip;
                if (ileng>0) {
                    if (info[ileng-1]==0) {
                        this->sesData->info = strdup(info);
                        passert(this->sesData->info);
                    } else {
                        this->sesData->info = (char*)malloc(ileng+1);
                        passert(this->sesData->info);
                        memcpy(this->sesData->info,info,ileng);
                        this->sesData->info[ileng]=0;
                    }
                }
                store_sessions();
            }

            wptr = this->createPacket(MATOCL_FUSE_REGISTER,(status==STATUS_OK)?((this->version>=0x01061A)?35:(this->version>=0x010615)?25:(this->version>=0x010601)?21:13):1);
            if (status!=STATUS_OK) {
                put8bit(&wptr,status);
                return;
            }
            sessionid = this->sesData->sessionid;
            if (this->version==0x010615) {
                put32bit(&wptr,0);
            } else if (this->version>=0x010616) {
                put16bit(&wptr,VERSMAJ);
                put8bit(&wptr,VERSMID);
                put8bit(&wptr,VERSMIN);
            }
            put32bit(&wptr,sessionid);
            put8bit(&wptr,sesflags);
            put32bit(&wptr,rootuid);
            put32bit(&wptr,rootgid);
            if (this->version>=0x010601) {
                put32bit(&wptr,mapalluid);
                put32bit(&wptr,mapallgid);
            }
            if (this->version>=0x01061A) {
                put8bit(&wptr,mingoal);
                put8bit(&wptr,maxgoal);
                put32bit(&wptr,mintrashtime);
                put32bit(&wptr,maxtrashtime);
            }
            this->registered = 1;
            return;
        case REGISTER_NEWMETASESSION:
            if (length<73) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.5 - wrong size (%"PRIu32"/>=73)",length);
                this->mode = KILL;
                return;
            }
            this->version = get32bit(&rptr);
            ileng = get32bit(&rptr);
            if (length!=73+ileng && length!=73+16+ileng) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.5 - wrong size (%"PRIu32"/73+ileng(%"PRIu32")[+16])",length,ileng);
                this->mode = KILL;
                return;
            }
            info = (const char*)rptr;
            rptr+=ileng;
            if (length==73+16+ileng) {
                status = exports_check(this->peerip,this->version,1,NULL,this->passwordrnd,rptr,&sesflags,&rootuid,&rootgid,&mapalluid,&mapallgid,&mingoal,&maxgoal,&mintrashtime,&maxtrashtime);
            } else {
                status = exports_check(this->peerip,this->version,1,NULL,NULL,NULL,&sesflags,&rootuid,&rootgid,&mapalluid,&mapallgid,&mingoal,&maxgoal,&mintrashtime,&maxtrashtime);
            }
            if (status==STATUS_OK) {
                this->sesData = CClientConn::new_session(1,0);
                if (this->sesData==NULL) {
                    syslog(LOG_NOTICE,"can't allocate session record");
                    this->mode = KILL;
                    return;
                }
                this->sesData->rootinode = 0;
                this->sesData->sesflags = sesflags;
                this->sesData->rootuid = 0;
                this->sesData->rootgid = 0;
                this->sesData->mapalluid = 0;
                this->sesData->mapallgid = 0;
                this->sesData->mingoal = mingoal;
                this->sesData->maxgoal = maxgoal;
                this->sesData->mintrashtime = mintrashtime;
                this->sesData->maxtrashtime = maxtrashtime;
                this->sesData->peerip = this->peerip;
                if (ileng>0) {
                    if (info[ileng-1]==0) {
                        this->sesData->info = strdup(info);
                        passert(this->sesData->info);
                    } else {
                        this->sesData->info = (char*)malloc(ileng+1);
                        passert(this->sesData->info);
                        memcpy(this->sesData->info,info,ileng);
                        this->sesData->info[ileng]=0;
                    }
                }

                store_sessions();
            }

            wptr = this->createPacket(MATOCL_FUSE_REGISTER,(status==STATUS_OK)?((this->version>=0x01061A)?19:(this->version>=0x010615)?9:5):1);
            if (status!=STATUS_OK) {
                put8bit(&wptr,status);
                return;
            }
            sessionid = this->sesData->sessionid;
            if (this->version>=0x010615) {
                put16bit(&wptr,VERSMAJ);
                put8bit(&wptr,VERSMID);
                put8bit(&wptr,VERSMIN);
            }
            put32bit(&wptr,sessionid);
            put8bit(&wptr,sesflags);
            if (this->version>=0x01061A) {
                put8bit(&wptr,mingoal);
                put8bit(&wptr,maxgoal);
                put32bit(&wptr,mintrashtime);
                put32bit(&wptr,maxtrashtime);
            }
            this->registered = 1;
            return;
        case REGISTER_RECONNECT:
        case REGISTER_TOOLS:
            if (length<73) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.%"PRIu8" - wrong size (%"PRIu32"/73)",rcode,length);
                this->mode = KILL;
                return;
            }
            sessionid = get32bit(&rptr);
            this->version = get32bit(&rptr);
            this->sesData = find_session(sessionid);
            if (this->sesData==NULL) {
                status = ERROR_BADSESSIONID;
            } else {
                if ((this->sesData->sesflags&SESFLAG_DYNAMICIP)==0 && this->peerip!=this->sesData->peerip) {
                    status = ERROR_EACCES;
                } else {
                    status = STATUS_OK;
                }
            }
            wptr = this->createPacket(MATOCL_FUSE_REGISTER,1);
            put8bit(&wptr,status);
            if (status!=STATUS_OK) {
                return;
            }
            this->registered = (rcode==3)?1:100;
            return;
        case REGISTER_CLOSESESSION:
            if (length<69) {
                syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL.6 - wrong size (%"PRIu32"/69)",length);
                this->mode = KILL;
                return;
            }
            sessionid = get32bit(&rptr);
            close_session(sessionid);
            this->mode = KILL;
            return;
        }
        syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER/ACL - wrong rcode (%"PRIu8")",rcode);
        this->mode = KILL;
        return;
    } else {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_REGISTER - wrong register blob");
        this->mode = KILL;
        return;
    }
}

void CClientConn::fuse_reserved_inodes(const uint8_t *data,uint32_t length) 
{
    if ((length&0x3)!=0) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_RESERVED_INODES - wrong size (%"PRIu32"/N*4)",length);
        this->mode = KILL;
        return;
    }

    const uint8_t *ptr = data;
    filelist **ofpptr = &(this->sesData->openedfiles);
    length >>= 2;

    uint32_t inode=0;
    if (length) {
        length--;
        inode = get32bit(&ptr);
    }

    filelist *ofptr;
    while ((ofptr=*ofpptr) && inode>0) {
        if (ofptr->inode<inode) {
            fs_release(ofptr->inode,this->sesData->sessionid);
            *ofpptr = ofptr->next;
            free(ofptr);
        } else if (ofptr->inode>inode) {
            if (fs_acquire(inode,this->sesData->sessionid)==STATUS_OK) {
                ofptr = (filelist*)malloc(sizeof(filelist));
                passert(ofptr);
                ofptr->next = *ofpptr;
                ofptr->inode = inode;
                *ofpptr = ofptr;
                ofpptr = &(ofptr->next);
            }
            if (length) {
                length--;
                inode = get32bit(&ptr);
            } else {
                inode=0;
            }
        } else {
            ofpptr = &(ofptr->next);
            if (length) {
                length--;
                inode = get32bit(&ptr);
            } else {
                inode=0;
            }
        }
    }

    while (inode>0) {
        if (fs_acquire(inode,this->sesData->sessionid)==STATUS_OK) {
            ofptr = (filelist*)malloc(sizeof(filelist));
            passert(ofptr);
            ofptr->next = *ofpptr;
            ofptr->inode = inode;
            *ofpptr = ofptr;
            ofpptr = &(ofptr->next);
        }
        if (length) {
            length--;
            inode = get32bit(&ptr);
        } else {
            inode=0;
        }
    }

    while ((ofptr=*ofpptr)) {
        fs_release(ofptr->inode,this->sesData->sessionid);
        *ofpptr = ofptr->next;
        free(ofptr);
    }

}

void CClientConn::fuse_statfs(const uint8_t *data,uint32_t length)
{
    if (length!=4) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_STATFS - wrong size (%"PRIu32"/4)",length);
        this->mode = KILL;
        return;
    }

    uint32_t inodes;
    uint32_t msgid = get32bit(&data);
    uint64_t totalspace,availspace,trashspace,reservedspace;
    fs_statfs(this->sesData->rootinode,this->sesData->sesflags,&totalspace,&availspace,&trashspace,&reservedspace,&inodes);

    uint8_t *ptr = this->createPacket(MATOCL_FUSE_STATFS,40);
    put32bit(&ptr,msgid);
    put64bit(&ptr,totalspace);
    put64bit(&ptr,availspace);
    put64bit(&ptr,trashspace);
    put64bit(&ptr,reservedspace);
    put32bit(&ptr,inodes);
    if (this->sesData) {
        this->sesData->curOpStats[0]++;
    }
}

void CClientConn::fuse_access(const uint8_t *data,uint32_t length) 
{
    if (length!=17) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_ACCESS - wrong size (%"PRIu32"/17)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid = get32bit(&data);
    uint32_t gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint8_t modemask = get8bit(&data);
    uint8_t status = fs_access(this->sesData->rootinode,this->sesData->sesflags,inode,uid,gid,modemask);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_ACCESS,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
}

void CClientConn::fuse_lookup(const uint8_t *data,uint32_t length)
{
    if (length<17) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_LOOKUP - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t nleng = get8bit(&data);

    if (length!=17U+nleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_LOOKUP - wrong size (%"PRIu32":nleng=%"PRIu8")",length,nleng);
        this->mode = KILL;
        return;
    }

    const uint8_t *name = data;
    data += nleng;
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);

    uint32_t newinode;
    uint8_t attr[35];
    uint8_t status = fs_lookup(this->sesData->rootinode,this->sesData->sesflags,inode,nleng,name,uid,gid,auid,agid,&newinode,attr);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_LOOKUP,(status!=STATUS_OK)?5:43);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,newinode);
        memcpy(ptr,attr,35);
    }

    if (this->sesData) {
        this->sesData->curOpStats[3]++;
    }
}

void CClientConn::fuse_getattr(const uint8_t *data,uint32_t length)
{
    if (length!=8 && length!=16) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETATTR - wrong size (%"PRIu32"/8,16)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid,gid,auid,agid;
    if (length==16) {
        auid = uid = get32bit(&data);
        agid = gid = get32bit(&data);
        ugid_remap(&uid,&gid);
    } else {
        auid = uid = 12345;
        agid = gid = 12345;
    }

    uint8_t attr[35];
    uint8_t status = fs_getattr(this->sesData->rootinode,this->sesData->sesflags,inode,uid,gid,auid,agid,attr);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETATTR,(status!=STATUS_OK)?5:39);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        memcpy(ptr,attr,35);
    }

    if (this->sesData) {
        this->sesData->curOpStats[1]++;
    }
}

void CClientConn::fuse_setattr(const uint8_t *data,uint32_t length) 
{
    if (length!=35 && length!=36) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETATTR - wrong size (%"PRIu32"/35|36)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint16_t setmask = get8bit(&data);
    uint16_t attrmode = get16bit(&data);
    uint32_t attruid = get32bit(&data);
    uint32_t attrgid = get32bit(&data);
    uint32_t attratime = get32bit(&data);
    uint32_t attrmtime = get32bit(&data);
    uint8_t sugidclearmode = length==36 ? get8bit(&data) : SUGID_CLEAR_MODE_ALWAYS;// this is safest option

    uint8_t status;
    uint8_t attr[35];
    if (setmask&(SET_GOAL_FLAG|SET_LENGTH_FLAG|SET_OPENED_FLAG)) {
        status = ERROR_EINVAL;
    } else {
        status = fs_setattr(this->sesData->rootinode,this->sesData->sesflags,inode,uid,gid,auid,agid,setmask,attrmode,attruid,attrgid,attratime,attrmtime,sugidclearmode,attr);
    }

    uint8_t *ptr = this->createPacket(MATOCL_FUSE_SETATTR,(status!=STATUS_OK)?5:39);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        memcpy(ptr,attr,35);
    }
    if (this->sesData) {
        this->sesData->curOpStats[2]++;
    }
}

void CClientConn::fuse_truncate(const uint8_t *data,uint32_t length)
{
    if (length!=24 && length!=25) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_TRUNCATE - wrong size (%"PRIu32"/24|25)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t opened = length==25 ? get8bit(&data) : 0;
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    if (length==24) {
        if (uid==0 && gid!=0) {	// stupid "opened" patch for old clients
            opened = 1;
        }
    }
    ugid_remap(&uid,&gid);

    chunklist *cl;
    uint8_t attr[35];
    uint64_t chunkid;
    uint64_t attrlength = get64bit(&data);
    uint8_t status = fs_try_setlength(this->sesData->rootinode,this->sesData->sesflags,inode,opened,uid,gid,auid,agid,attrlength,attr,&chunkid);
    if (status==ERROR_DELAYED) {
        cl = (chunklist*)malloc(sizeof(chunklist));
        passert(cl);
        cl->chunkid = chunkid;
        cl->qid = msgid;
        cl->inode = inode;
        cl->uid = uid;
        cl->gid = gid;
        cl->auid = auid;
        cl->agid = agid;
        cl->fleng = attrlength;
        cl->type = FUSE_TRUNCATE;
        cl->next = this->chunkDelayedOps;
        this->chunkDelayedOps = cl;
        if (this->sesData) {
            this->sesData->curOpStats[2]++;
        }
        return;
    }

    if (status==STATUS_OK) {
        status = fs_do_setlength(this->sesData->rootinode,this->sesData->sesflags,inode,uid,gid,auid,agid,attrlength,attr);
    }
    if (status==STATUS_OK) {
        dcm_modify(inode,this->sesData->sessionid);
    }

    uint8_t *ptr = this->createPacket(MATOCL_FUSE_TRUNCATE,(status!=STATUS_OK)?5:39);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        memcpy(ptr,attr,35);
    }
    if (this->sesData) {
        this->sesData->curOpStats[2]++;
    }
}

void CClientConn::fuse_readlink(const uint8_t *data,uint32_t length)
{
    if (length!=8) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_READLINK - wrong size (%"PRIu32"/8)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t pleng;
    uint8_t *path;
    uint8_t status = fs_readlink(this->sesData->rootinode,this->sesData->sesflags,inode,&pleng,&path);

    uint8_t *ptr = this->createPacket(MATOCL_FUSE_READLINK,(status!=STATUS_OK)?5:8+pleng+1);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,pleng+1);
        if (pleng>0) {
            memcpy(ptr,path,pleng);
        }
        ptr[pleng]=0;
    }
    if (this->sesData) {
        this->sesData->curOpStats[7]++;
    }
}

void CClientConn::fuse_symlink(const uint8_t *data,uint32_t length)
{
    if (length<21) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SYMLINK - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }
    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t nleng = get8bit(&data);
    if (length<21U+nleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SYMLINK - wrong size (%"PRIu32":nleng=%"PRIu8")",length,nleng);
        this->mode = KILL;
        return;
    }

    const uint8_t *name = data;
    data += nleng;
    uint32_t pleng = get32bit(&data);
    if (length!=21U+nleng+pleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SYMLINK - wrong size (%"PRIu32":nleng=%"PRIu8":pleng=%"PRIu32")",length,nleng,pleng);
        this->mode = KILL;
        return;
    }

    const uint8_t *path = data;
    data += pleng;
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    while (pleng>0 && path[pleng-1]==0) {
        pleng--;
    }

    uint32_t newinode;
    uint8_t attr[35];
    uint8_t status = fs_symlink(this->sesData->rootinode,this->sesData->sesflags,inode,nleng,name,pleng,path,uid,gid,auid,agid,&newinode,attr);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_SYMLINK,(status!=STATUS_OK)?5:43);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,newinode);
        memcpy(ptr,attr,35);
    }
    if (this->sesData) {
        this->sesData->curOpStats[6]++;
    }
}

void CClientConn::fuse_mknod(const uint8_t *data,uint32_t length) 
{
    if (length<24) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_MKNOD - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t nleng = get8bit(&data);
    if (length!=24U+nleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_MKNOD - wrong size (%"PRIu32":nleng=%"PRIu8")",length,nleng);
        this->mode = KILL;
        return;
    }

    const uint8_t *name = data;
    data += nleng;
    uint8_t type = get8bit(&data);
    uint16_t mode = get16bit(&data);
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint32_t rdev = get32bit(&data);

    uint8_t attr[35];
    uint32_t newinode;
    uint8_t status = fs_mknod(this->sesData->rootinode,this->sesData->sesflags,inode,nleng,name,type,mode,uid,gid,auid,agid,rdev,&newinode,attr);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_MKNOD,(status!=STATUS_OK)?5:43);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,newinode);
        memcpy(ptr,attr,35);
    }
    if (this->sesData) {
        this->sesData->curOpStats[8]++;
    }
}

void CClientConn::fuse_mkdir(const uint8_t *data,uint32_t length)
{
    if (length<19) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_MKDIR - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t nleng = get8bit(&data);
    if (length!=19U+nleng && length!=20U+nleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_MKDIR - wrong size (%"PRIu32":nleng=%"PRIu8")",length,nleng);
        this->mode = KILL;
        return;
    }

    const uint8_t *name = data;
    data += nleng;
    uint16_t mode = get16bit(&data);
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint8_t copysgid = (length==20U+nleng) ? get8bit(&data): 0 ; // by default do not copy sgid bit

    uint32_t newinode;
    uint8_t attr[35];
    uint8_t status = fs_mkdir(this->sesData->rootinode,this->sesData->sesflags,inode,nleng,name,mode,uid,gid,auid,agid,copysgid,&newinode,attr);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_MKDIR,(status!=STATUS_OK)?5:43);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,newinode);
        memcpy(ptr,attr,35);
    }
    if (this->sesData) {
        this->sesData->curOpStats[4]++;
    }
}

void CClientConn::fuse_unlink(const uint8_t *data,uint32_t length)
{
    if (length<17) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_UNLINK - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t nleng = get8bit(&data);
    if (length!=17U+nleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_UNLINK - wrong size (%"PRIu32":nleng=%"PRIu8")",length,nleng);
        this->mode = KILL;
        return;
    }
    const uint8_t *name = data;
    data += nleng;
    uint32_t uid = get32bit(&data);
    uint32_t gid = get32bit(&data);
    ugid_remap(&uid,&gid);

    uint8_t status = fs_unlink(this->sesData->rootinode,this->sesData->sesflags,inode,nleng,name,uid,gid);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_UNLINK,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
    if (this->sesData) {
        this->sesData->curOpStats[9]++;
    }
}

void CClientConn::fuse_rmdir(const uint8_t *data,uint32_t length) 
{
    if (length<17) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_RMDIR - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t nleng = get8bit(&data);
    if (length!=17U+nleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_RMDIR - wrong size (%"PRIu32":nleng=%"PRIu8")",length,nleng);
        this->mode = KILL;
        return;
    }

    const uint8_t *name = data;
    data += nleng;
    uint32_t uid = get32bit(&data);
    uint32_t gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint8_t status = fs_rmdir(this->sesData->rootinode,this->sesData->sesflags,inode,nleng,name,uid,gid);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_RMDIR,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
    if (this->sesData) {
        this->sesData->curOpStats[5]++;
    }
}

void CClientConn::fuse_rename(const uint8_t *data,uint32_t length) 
{
    if (length<22) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_RENAME - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode_src = get32bit(&data);
    uint8_t nleng_src = get8bit(&data);
    if (length<22U+nleng_src) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_RENAME - wrong size (%"PRIu32":nleng_src=%"PRIu8")",length,nleng_src);
        this->mode = KILL;
        return;
    }

    const uint8_t *name_src = data;
    data += nleng_src;
    uint32_t inode_dst = get32bit(&data);
    uint8_t nleng_dst = get8bit(&data);
    if (length!=22U+nleng_src+nleng_dst) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_RENAME - wrong size (%"PRIu32":nleng_src=%"PRIu8":nleng_dst=%"PRIu8")",length,nleng_src,nleng_dst);
        this->mode = KILL;
        return;
    }
    const uint8_t *name_dst = data;
    data += nleng_dst;

    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);

    uint32_t inode;
    uint8_t attr[35];
    uint8_t status = fs_rename(this->sesData->rootinode,this->sesData->sesflags,inode_src,nleng_src,name_src,inode_dst,nleng_dst,name_dst,uid,gid,auid,agid,&inode,attr);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_RENAME,(this->version>=0x010615 && status==STATUS_OK) ? 43 : 5);

    put32bit(&ptr,msgid);
    if (this->version>=0x010615 && status==STATUS_OK) {
        put32bit(&ptr,inode);
        memcpy(ptr,attr,35);
    } else {
        put8bit(&ptr,status);
    }

    if (this->sesData) {
        this->sesData->curOpStats[10]++;
    }
}

void CClientConn::fuse_link(const uint8_t *data,uint32_t length)
{
    if (length<21) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_LINK - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t inode_dst = get32bit(&data);
    uint8_t nleng_dst = get8bit(&data);
    if (length!=21U+nleng_dst) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_LINK - wrong size (%"PRIu32":nleng_dst=%"PRIu8")",length,nleng_dst);
        this->mode = KILL;
        return;
    }

    const uint8_t *name_dst = data;
    data += nleng_dst;
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);

    uint32_t newinode;
    uint8_t attr[35];
    uint8_t status = fs_link(this->sesData->rootinode,this->sesData->sesflags,inode,inode_dst,nleng_dst,name_dst,uid,gid,auid,agid,&newinode,attr);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_LINK,(status!=STATUS_OK)?5:43);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,newinode);
        memcpy(ptr,attr,35);
    }
    if (this->sesData) {
        this->sesData->curOpStats[11]++;
    }
}

void CClientConn::fuse_getdir(const uint8_t *data,uint32_t length)
{
    if (length!=16 && length!=17) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETDIR - wrong size (%"PRIu32"/16|17)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint8_t flags  = (length==17) ? get8bit(&data) : 0;

    uint32_t dleng;
    void *custom;
    uint8_t status = fs_readdir_size(this->sesData->rootinode,this->sesData->sesflags,inode,uid,gid,flags,&custom,&dleng);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETDIR,(status!=STATUS_OK)?5:4+dleng);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        fs_readdir_data(this->sesData->rootinode,this->sesData->sesflags,uid,gid,auid,agid,flags,custom,ptr);
    }
    if (this->sesData) {
        this->sesData->curOpStats[12]++;
    }
}

void CClientConn::fuse_open(const uint8_t *data,uint32_t length)
{
    if (length!=17) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_OPEN - wrong size (%"PRIu32"/17)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid,gid,auid,agid;
    auid = uid = get32bit(&data);
    agid = gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint8_t flags = get8bit(&data);

    uint8_t attr[35];
    uint8_t status = insert_openfile(this->sesData,inode);
    if (status==STATUS_OK) {
        status = fs_opencheck(this->sesData->rootinode,this->sesData->sesflags,inode,uid,gid,auid,agid,flags,attr);
    }

    uint8_t *ptr;
    if (this->version>=0x010609 && status==STATUS_OK) {
        int allowcache = dcm_open(inode,this->sesData->sessionid);
        if (allowcache==0) {
            attr[1]&=(0xFF^(MATTR_ALLOWDATACACHE<<4));
        }
        ptr = this->createPacket(MATOCL_FUSE_OPEN,39);
        put32bit(&ptr,msgid);
        memcpy(ptr,attr,35);
    } else {
        ptr = this->createPacket(MATOCL_FUSE_OPEN,5);
        put32bit(&ptr,msgid);
        put8bit(&ptr,status);
    }

    if (this->sesData) {
        this->sesData->curOpStats[13]++;
    }
}

void CClientConn::fuse_read_chunk(const uint8_t *data,uint32_t length)
{
    if (length!=12) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_READ_CHUNK - wrong size (%"PRIu32"/12)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t indx = get32bit(&data);

    uint64_t chunkid;
    uint64_t fleng;
    uint32_t version;
    uint8_t count;
    uint8_t loc[100*6];
    uint8_t status = fs_readchunk(inode,indx,&chunkid,&fleng);
    if (status==STATUS_OK) {
        if (chunkid>0) {
            status = get_version_locations(chunkid,this->peerip,&version,&count,loc);
        } else {
            version = 0;
            count = 0;
        }
    }

    if (status!=STATUS_OK) {
        uint8_t *ptr = this->createPacket(MATOCL_FUSE_READ_CHUNK,5);
        put32bit(&ptr,msgid);
        put8bit(&ptr,status);
        return;
    }

    dcm_access(inode, this->sesData->sessionid);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_READ_CHUNK,24+count*6);
    put32bit(&ptr,msgid);
    put64bit(&ptr,fleng);
    put64bit(&ptr,chunkid);
    put32bit(&ptr,version);
    memcpy(ptr,loc,count*6);

    if (this->sesData) {
        this->sesData->curOpStats[14]++;
    }
}

void CClientConn::fuse_write_chunk(const uint8_t *data,uint32_t length)
{
    if (length!=12) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_WRITE_CHUNK - wrong size (%"PRIu32"/12)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t indx = get32bit(&data);
    uint64_t chunkid;
    uint8_t opflag;
    uint64_t fleng;
    uint8_t status = (this->sesData->sesflags&SESFLAG_READONLY) ? ERROR_EROFS : fs_writechunk(inode,indx,&chunkid,&fleng,&opflag);
    if (status!=STATUS_OK) {
        uint8_t *ptr = this->createPacket(MATOCL_FUSE_WRITE_CHUNK,5);
        put32bit(&ptr,msgid);
        put8bit(&ptr,status);
        return;
    }

    if (opflag) {	// wait for operation end
        chunklist *cl = (chunklist*)malloc(sizeof(chunklist));
        passert(cl);
        cl->inode = inode;
        cl->chunkid = chunkid;
        cl->qid = msgid;
        cl->fleng = fleng;
        cl->type = FUSE_WRITE;
        cl->next = this->chunkDelayedOps;
        this->chunkDelayedOps = cl;
    } else {	// return status immediately
        dcm_modify(inode,this->sesData->sessionid);

        uint32_t version;
        uint8_t count;
        uint8_t loc[100*6];
        status=get_version_locations(chunkid,this->peerip,&version,&count,loc);
        if (status!=STATUS_OK) {
            uint8_t *ptr = this->createPacket(MATOCL_FUSE_WRITE_CHUNK,5);
            put32bit(&ptr,msgid);
            put8bit(&ptr,status);
            fs_writeend(0,0,chunkid);	// ignore status - just do it.
            return;
        }

        uint8_t *ptr = this->createPacket(MATOCL_FUSE_WRITE_CHUNK,24+count*6);
        put32bit(&ptr,msgid);
        put64bit(&ptr,fleng);
        put64bit(&ptr,chunkid);
        put32bit(&ptr,version);
        memcpy(ptr,loc,count*6);
    }

    if (this->sesData) {
        this->sesData->curOpStats[15]++;
    }
}

void CClientConn::fuse_write_chunk_end(const uint8_t *data,uint32_t length) 
{
    if (length!=24) {
        syslog(LOG_NOTICE,"CLTOMA_WRITE_CHUNK_END - wrong size (%"PRIu32"/24)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint64_t chunkid = get64bit(&data);
    uint32_t inode = get32bit(&data);
    uint64_t fleng = get64bit(&data);
    uint8_t status = (this->sesData->sesflags&SESFLAG_READONLY) ? ERROR_EROFS : fs_writeend(inode,fleng,chunkid);

    dcm_modify(inode,this->sesData->sessionid);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_WRITE_CHUNK_END,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
}

void CClientConn::fuse_repair(const uint8_t *data,uint32_t length) 
{
    if (length!=16) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_REPAIR - wrong size (%"PRIu32"/16)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid = get32bit(&data);
    uint32_t gid = get32bit(&data);
    ugid_remap(&uid,&gid);

    uint32_t chunksnotchanged,chunkserased,chunksrepaired;
    uint8_t status = fs_repair(this->sesData->rootinode,this->sesData->sesflags,inode,uid,gid,&chunksnotchanged,&chunkserased,&chunksrepaired);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_REPAIR,(status!=STATUS_OK)?5:16);
    put32bit(&ptr,msgid);
    if (status!=0) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,chunksnotchanged);
        put32bit(&ptr,chunkserased);
        put32bit(&ptr,chunksrepaired);
    }
}

void CClientConn::fuse_check(const uint8_t *data,uint32_t length) 
{
    if (length!=8) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_CHECK - wrong size (%"PRIu32"/8)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t i,chunkcount[11];
    uint8_t status = fs_checkfile(this->sesData->rootinode,this->sesData->sesflags,inode,chunkcount);
    if (status!=STATUS_OK) {
        uint8_t *ptr = this->createPacket(MATOCL_FUSE_CHECK,5);
        put32bit(&ptr,msgid);
        put8bit(&ptr,status);
    } else {
        if (this->version>=0x010617) {
            uint8_t *ptr = this->createPacket(MATOCL_FUSE_CHECK,48);
            put32bit(&ptr,msgid);
            for (i=0 ; i<11 ; i++) {
                put32bit(&ptr,chunkcount[i]);
            }
        } else {
            uint8_t j=0;
            for (i=0 ; i<11 ; i++) {
                if (chunkcount[i]>0) {
                    j++;
                }
            }

            uint8_t *ptr = this->createPacket(MATOCL_FUSE_CHECK,4+3*j);
            put32bit(&ptr,msgid);
            for (i=0 ; i<11 ; i++) {
                if (chunkcount[i]>0) {
                    put8bit(&ptr,i);
                    if (chunkcount[i]<=65535) {
                        put16bit(&ptr,chunkcount[i]);
                    } else {
                        put16bit(&ptr,65535);
                    }
                }
            }
        }
    }
}

void CClientConn::fuse_gettrashtime(const uint8_t *data,uint32_t length)
{
    if (length!=9) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETTRASHTIME - wrong size (%"PRIu32"/9)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t gmode = get8bit(&data);

    void *fptr,*dptr;
    uint32_t fnodes,dnodes;
    uint8_t status = fs_gettrashtime_prepare(this->sesData->rootinode,this->sesData->sesflags,inode,gmode,&fptr,&dptr,&fnodes,&dnodes);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETTRASHTIME,(status!=STATUS_OK)?5:12+8*(fnodes+dnodes));
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,fnodes);
        put32bit(&ptr,dnodes);
        fs_gettrashtime_store(fptr,dptr,ptr);
    }
}

void CClientConn::fuse_settrashtime(const uint8_t *data,uint32_t length)
{
    if (length!=17) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETTRASHTIME - wrong size (%"PRIu32"/17)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid = get32bit(&data);
    ugid_remap(&uid,NULL);
    uint32_t trashtime = get32bit(&data);
    uint8_t smode = get8bit(&data);
    // limits check
    uint8_t status = STATUS_OK;
    switch (smode&SMODE_TMASK) {
    case SMODE_SET:
        if (trashtime<this->sesData->mintrashtime || trashtime>this->sesData->maxtrashtime) {
            status = ERROR_EPERM;
        }
        break;
    case SMODE_INCREASE:
        if (trashtime>this->sesData->maxtrashtime) {
            status = ERROR_EPERM;
        }
        break;
    case SMODE_DECREASE:
        if (trashtime<this->sesData->mintrashtime) {
            status = ERROR_EPERM;
        }
        break;
    }

    //
    uint32_t changed,notchanged,notpermitted;
    if (status==STATUS_OK) {
        status = fs_settrashtime(this->sesData->rootinode,this->sesData->sesflags,inode,uid,trashtime,smode,&changed,&notchanged,&notpermitted);
    }
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_SETTRASHTIME,(status!=STATUS_OK)?5:16);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,changed);
        put32bit(&ptr,notchanged);
        put32bit(&ptr,notpermitted);
    }
}

void CClientConn::fuse_getgoal(const uint8_t *data,uint32_t length)
{
    if (length!=9) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETGOAL - wrong size (%"PRIu32"/9)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t gmode = get8bit(&data);
    uint32_t fgtab[10],dgtab[10];
    uint8_t status = fs_getgoal(this->sesData->rootinode,this->sesData->sesflags,inode,gmode,fgtab,dgtab);

    uint8_t i,fn=0,dn=0;
    if (status==STATUS_OK) {
        for (i=1 ; i<10 ; i++) {
            if (fgtab[i]) {
                fn++;
            }
            if (dgtab[i]) {
                dn++;
            }
        }
    }

    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETGOAL,(status!=STATUS_OK)?5:6+5*(fn+dn));
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put8bit(&ptr,fn);
        put8bit(&ptr,dn);
        for (i=1 ; i<10 ; i++) {
            if (fgtab[i]) {
                put8bit(&ptr,i);
                put32bit(&ptr,fgtab[i]);
            }
        }
        for (i=1 ; i<10 ; i++) {
            if (dgtab[i]) {
                put8bit(&ptr,i);
                put32bit(&ptr,dgtab[i]);
            }
        }
    }
}

void CClientConn::fuse_setgoal(const uint8_t *data,uint32_t length)
{
    if (length!=14) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETGOAL - wrong size (%"PRIu32"/14)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid = get32bit(&data);
    ugid_remap(&uid,NULL);
    uint8_t goal = get8bit(&data);
    uint8_t smode = get8bit(&data);
    // limits check
    uint8_t status = STATUS_OK;
    switch (smode&SMODE_TMASK) {
    case SMODE_SET:
        if (goal<this->sesData->mingoal || goal>this->sesData->maxgoal) {
            status = ERROR_EPERM;
        }
        break;
    case SMODE_INCREASE:
        if (goal>this->sesData->maxgoal) {
            status = ERROR_EPERM;
        }
        break;
    case SMODE_DECREASE:
        if (goal<this->sesData->mingoal) {
            status = ERROR_EPERM;
        }
        break;
    }
    // 
    if (goal<1 || goal>9) {
        status = ERROR_EINVAL;
    }

#if VERSHEX>=0x010700
    uint32_t changed,notchanged,notpermitted,quotaexceeded;
#else
    uint32_t changed,notchanged,notpermitted;
#endif

    if (status==STATUS_OK) {
#if VERSHEX>=0x010700
        status = fs_setgoal(this->sesData->rootinode,this->sesData->sesflags,inode,uid,goal,smode,&changed,&notchanged,&notpermitted,&quotaexceeded);
#else
        status = fs_setgoal(this->sesData->rootinode,this->sesData->sesflags,inode,uid,goal,smode,&changed,&notchanged,&notpermitted);
#endif
    }

    uint8_t *ptr;
    if (this->version>=0x010700) {
        ptr = this->createPacket(MATOCL_FUSE_SETGOAL,(status!=STATUS_OK)?5:20);
    } else {
        ptr = this->createPacket(MATOCL_FUSE_SETGOAL,(status!=STATUS_OK)?5:16);
    }
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,changed);
        put32bit(&ptr,notchanged);
        put32bit(&ptr,notpermitted);
        if (this->version>=0x010700) {
#if VERSHEX>=0x010700
            put32bit(&ptr,quotaexceeded);
#else
            put32bit(&ptr,0);
#endif
        }
    }
}

void CClientConn::fuse_geteattr(const uint8_t *data,uint32_t length) 
{
    if (length!=9) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETEATTR - wrong size (%"PRIu32"/9)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t gmode = get8bit(&data);
    uint32_t feattrtab[16],deattrtab[16];
    uint8_t status = fs_geteattr(this->sesData->rootinode,this->sesData->sesflags,inode,gmode,feattrtab,deattrtab);

    uint8_t i,fn=0,dn=0;
    if (status==STATUS_OK) {
        for (i=0 ; i<16 ; i++) {
            if (feattrtab[i]) {
                fn++;
            }
            if (deattrtab[i]) {
                dn++;
            }
        }
    }

    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETEATTR,(status!=STATUS_OK)?5:6+5*(fn+dn));
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put8bit(&ptr,fn);
        put8bit(&ptr,dn);
        for (i=0 ; i<16 ; i++) {
            if (feattrtab[i]) {
                put8bit(&ptr,i);
                put32bit(&ptr,feattrtab[i]);
            }
        }
        for (i=0 ; i<16 ; i++) {
            if (deattrtab[i]) {
                put8bit(&ptr,i);
                put32bit(&ptr,deattrtab[i]);
            }
        }
    }
}

void CClientConn::fuse_seteattr(const uint8_t *data,uint32_t length)
{
    if (length!=14) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETEATTR - wrong size (%"PRIu32"/14)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t uid = get32bit(&data);
    ugid_remap(&uid,NULL);
    uint8_t eattr = get8bit(&data);
    uint8_t smode = get8bit(&data);

    uint32_t changed,notchanged,notpermitted;
    uint8_t status = fs_seteattr(this->sesData->rootinode,this->sesData->sesflags,inode,uid,eattr,smode,&changed,&notchanged,&notpermitted);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_SETEATTR,(status!=STATUS_OK)?5:16);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,changed);
        put32bit(&ptr,notchanged);
        put32bit(&ptr,notpermitted);
    }
}

void CClientConn::fuse_getxattr(const uint8_t *data,uint32_t length)
{
    if (length<19) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETXATTR - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t opened = get8bit(&data);
    uint32_t uid = get32bit(&data);
    uint32_t gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint8_t anleng = get8bit(&data);
    const uint8_t *attrname = data;
    data+=anleng;

    if (length!=19U+anleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETXATTR - wrong size (%"PRIu32":anleng=%"PRIu8")",length,anleng);
        this->mode = KILL;
        return;
    }

    uint8_t mode = get8bit(&data);
    if (mode!=MFS_XATTR_GETA_DATA && mode!=MFS_XATTR_LENGTH_ONLY) {
        uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETXATTR,5);
        put32bit(&ptr,msgid);
        put8bit(&ptr,ERROR_EINVAL);
    } else if (anleng==0) {
        void *xanode;
        uint32_t xasize;
        uint8_t status = fs_listxattr_leng(this->sesData->rootinode,this->sesData->sesflags,inode,opened,uid,gid,&xanode,&xasize);
        uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETXATTR,(status!=STATUS_OK)?5:8+((mode==MFS_XATTR_GETA_DATA)?xasize:0));
        put32bit(&ptr,msgid);
        if (status!=STATUS_OK) {
            put8bit(&ptr,status);
        } else {
            put32bit(&ptr,xasize);
            if (mode==MFS_XATTR_GETA_DATA && xasize>0) {
                fs_listxattr_data(xanode,ptr);
            }
        }
    } else {
        uint8_t *attrvalue;
        uint32_t avleng;
        uint8_t status = fs_getxattr(this->sesData->rootinode,this->sesData->sesflags,inode,opened,uid,gid,anleng,attrname,&avleng,&attrvalue);
        uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETXATTR,(status!=STATUS_OK)?5:8+((mode==MFS_XATTR_GETA_DATA)?avleng:0));
        put32bit(&ptr,msgid);
        if (status!=STATUS_OK) {
            put8bit(&ptr,status);
        } else {
            put32bit(&ptr,avleng);
            if (mode==MFS_XATTR_GETA_DATA && avleng>0) {
                memcpy(ptr,attrvalue,avleng);
            }
        }
    }
}

void CClientConn::fuse_setxattr(const uint8_t *data,uint32_t length) 
{
    if (length<23) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETXATTR - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t opened = get8bit(&data);
    uint32_t uid = get32bit(&data);
    uint32_t gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint8_t anleng = get8bit(&data);

    if (length<23U+anleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETXATTR - wrong size (%"PRIu32":anleng=%"PRIu8")",length,anleng);
        this->mode = KILL;
        return;
    }

    const uint8_t *attrname = data;
    data += anleng;
    uint32_t avleng = get32bit(&data);
    if (length!=23U+anleng+avleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETXATTR - wrong size (%"PRIu32":anleng=%"PRIu8":avleng=%"PRIu32")",length,anleng,avleng);
        this->mode = KILL;
        return;
    }

    const uint8_t *attrvalue = data;
    data += avleng;
    uint8_t mode = get8bit(&data);
    uint8_t status = fs_setxattr(this->sesData->rootinode,this->sesData->sesflags,inode,opened,uid,gid,anleng,attrname,avleng,attrvalue,mode);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_SETXATTR,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
}

void CClientConn::fuse_append(const uint8_t *data,uint32_t length)
{
    if (length!=20) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_APPEND - wrong size (%"PRIu32"/20)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t inode_src = get32bit(&data);
    uint32_t uid = get32bit(&data);
    uint32_t gid = get32bit(&data);
    ugid_remap(&uid,&gid);

    uint8_t status = fs_append(this->sesData->rootinode,this->sesData->sesflags,inode,inode_src,uid,gid);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_APPEND,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
}

void CClientConn::fuse_snapshot(const uint8_t *data,uint32_t length)
{
    if (length<22) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SNAPSHOT - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t inode_dst = get32bit(&data);
    uint8_t nleng_dst = get8bit(&data);
    if (length!=22U+nleng_dst) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SNAPSHOT - wrong size (%"PRIu32":nleng_dst=%"PRIu8")",length,nleng_dst);
        this->mode = KILL;
        return;
    }
    const uint8_t *name_dst = data;
    data += nleng_dst;
    uint32_t uid = get32bit(&data);
    uint32_t gid = get32bit(&data);
    ugid_remap(&uid,&gid);
    uint8_t canoverwrite = get8bit(&data);

    uint8_t status = fs_snapshot(this->sesData->rootinode,this->sesData->sesflags,inode,inode_dst,nleng_dst,name_dst,uid,gid,canoverwrite);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_SNAPSHOT,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
}

void CClientConn::fuse_quotacontrol(const uint8_t *data,uint32_t length)
{
    if (length!=65 && length!=9) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_QUOTACONTROL - wrong size (%"PRIu32")",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t flags = get8bit(&data);

    uint8_t del;
    uint32_t sinodes,hinodes,curinodes;
    uint64_t slength,ssize,srealsize,hlength,hsize,hrealsize,curlength,cursize,currealsize;
    if (length==65) {
        sinodes = get32bit(&data);
        slength = get64bit(&data);
        ssize = get64bit(&data);
        srealsize = get64bit(&data);
        hinodes = get32bit(&data);
        hlength = get64bit(&data);
        hsize = get64bit(&data);
        hrealsize = get64bit(&data);
        del=0;
    } else {
        del=1;
    }

    uint8_t status;
    if (flags && this->sesData->rootuid!=0) {
        status = ERROR_EACCES;
    } else {
        status = fs_quotacontrol(this->sesData->rootinode,this->sesData->sesflags,inode,del,&flags,&sinodes,&slength,&ssize,&srealsize,&hinodes,&hlength,&hsize,&hrealsize,&curinodes,&curlength,&cursize,&currealsize);
    }

    uint8_t *ptr = this->createPacket(MATOCL_FUSE_QUOTACONTROL,(status!=STATUS_OK)?5:89);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put8bit(&ptr,flags);
        put32bit(&ptr,sinodes);
        put64bit(&ptr,slength);
        put64bit(&ptr,ssize);
        put64bit(&ptr,srealsize);
        put32bit(&ptr,hinodes);
        put64bit(&ptr,hlength);
        put64bit(&ptr,hsize);
        put64bit(&ptr,hrealsize);
        put32bit(&ptr,curinodes);
        put64bit(&ptr,curlength);
        put64bit(&ptr,cursize);
        put64bit(&ptr,currealsize);
    }
}

void CClientConn::fuse_getdirstats_old(const uint8_t *data,uint32_t length)
{
    if (length!=8) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETDIRSTATS - wrong size (%"PRIu32"/8)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);

    uint32_t inodes,files,dirs,chunks;
    uint64_t leng,size,rsize;
    uint8_t status = fs_get_dir_stats(this->sesData->rootinode,this->sesData->sesflags,inode,&inodes,&dirs,&files,&chunks,&leng,&size,&rsize);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETDIRSTATS,(status!=STATUS_OK)?5:60);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,inodes);
        put32bit(&ptr,dirs);
        put32bit(&ptr,files);
        put32bit(&ptr,0);
        put32bit(&ptr,0);
        put32bit(&ptr,chunks);
        put32bit(&ptr,0);
        put32bit(&ptr,0);
        put64bit(&ptr,leng);
        put64bit(&ptr,size);
        put64bit(&ptr,rsize);
    }
}

void CClientConn::fuse_getdirstats(const uint8_t *data,uint32_t length)
{
    if (length!=8) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETDIRSTATS - wrong size (%"PRIu32"/8)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);

    uint32_t inodes,files,dirs,chunks;
    uint64_t leng,size,rsize;
    uint8_t status = fs_get_dir_stats(this->sesData->rootinode,this->sesData->sesflags,inode,&inodes,&dirs,&files,&chunks,&leng,&size,&rsize);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETDIRSTATS,(status!=STATUS_OK)?5:44);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,inodes);
        put32bit(&ptr,dirs);
        put32bit(&ptr,files);
        put32bit(&ptr,chunks);
        put64bit(&ptr,leng);
        put64bit(&ptr,size);
        put64bit(&ptr,rsize);
    }
}

void CClientConn::fuse_gettrash(const uint8_t *data,uint32_t length)
{
    if (length!=4) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETTRASH - wrong size (%"PRIu32"/4)",length);
        this->mode = KILL;
        return;
    }
    uint32_t msgid = get32bit(&data);

    uint32_t dleng;
    uint8_t status = fs_readtrash_size(this->sesData->rootinode,this->sesData->sesflags,&dleng);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETTRASH,(status!=STATUS_OK)?5:(4+dleng));
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        fs_readtrash_data(this->sesData->rootinode,this->sesData->sesflags,ptr);
    }
}

void CClientConn::fuse_getdetachedattr(const uint8_t *data,uint32_t length)
{
    if (length<8 || length>9) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETDETACHEDATTR - wrong size (%"PRIu32"/8,9)",length);
        this->mode = KILL;
        return;
    }
    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t dtype = (length==9) ? get8bit(&data) : DTYPE_UNKNOWN;

    uint8_t attr[35];
    uint8_t status = fs_getdetachedattr(this->sesData->rootinode,this->sesData->sesflags,inode,attr,dtype);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETDETACHEDATTR,(status!=STATUS_OK)?5:39);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        memcpy(ptr,attr,35);
    }
}

void CClientConn::fuse_gettrashpath(const uint8_t *data,uint32_t length)
{
    if (length!=8) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETTRASHPATH - wrong size (%"PRIu32"/8)",length);
        this->mode = KILL;
        return;
    }
    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);

    uint32_t pleng;
    uint8_t *path;
    uint8_t status = fs_gettrashpath(this->sesData->rootinode,this->sesData->sesflags,inode,&pleng,&path);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETTRASHPATH,(status!=STATUS_OK)?5:8+pleng+1);
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        put32bit(&ptr,pleng+1);
        if (pleng>0) {
            memcpy(ptr,path,pleng);
        }
        ptr[pleng]=0;
    }
}

void CClientConn::fuse_settrashpath(const uint8_t *data,uint32_t length)
{
    if (length<12) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETTRASHPATH - wrong size (%"PRIu32"/>=12)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint32_t pleng = get32bit(&data);
    if (length!=12+pleng) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_SETTRASHPATH - wrong size (%"PRIu32"/%"PRIu32")",length,12+pleng);
        this->mode = KILL;
        return;
    }
    const uint8_t *path = data;
    data += pleng;
    while (pleng>0 && path[pleng-1]==0) {
        pleng--;
    }

    uint8_t status = fs_settrashpath(this->sesData->rootinode,this->sesData->sesflags,inode,pleng,path);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_SETTRASHPATH,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
}

void CClientConn::fuse_undel(const uint8_t *data,uint32_t length)
{
    if (length!=8) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_UNDEL - wrong size (%"PRIu32"/8)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);
    uint8_t status = fs_undel(this->sesData->rootinode,this->sesData->sesflags,inode);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_UNDEL,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
}

void CClientConn::fuse_purge(const uint8_t *data,uint32_t length)
{
    if (length!=8) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_PURGE - wrong size (%"PRIu32"/8)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);
    uint32_t inode = get32bit(&data);

    uint8_t status = fs_purge(this->sesData->rootinode,this->sesData->sesflags,inode);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_PURGE,5);
    put32bit(&ptr,msgid);
    put8bit(&ptr,status);
}

void CClientConn::fuse_getreserved(const uint8_t *data,uint32_t length)
{
    if (length!=4) {
        syslog(LOG_NOTICE,"CLTOMA_FUSE_GETRESERVED - wrong size (%"PRIu32"/4)",length);
        this->mode = KILL;
        return;
    }

    uint32_t msgid = get32bit(&data);

    uint32_t dleng;
    uint8_t status = fs_readreserved_size(this->sesData->rootinode,this->sesData->sesflags,&dleng);
    uint8_t *ptr = this->createPacket(MATOCL_FUSE_GETRESERVED,(status!=STATUS_OK)?5:(4+dleng));
    put32bit(&ptr,msgid);
    if (status!=STATUS_OK) {
        put8bit(&ptr,status);
    } else {
        fs_readreserved_data(this->sesData->rootinode,this->sesData->sesflags,ptr);
    }
}
