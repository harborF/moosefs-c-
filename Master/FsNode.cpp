#include "FsNode.h"
#include "ChunkMgr.h"
#include "FileIDMgr.h"
#include "FileSysMgr.h"

CFsNode* CFsNode::s_root = NULL;
CFsNode* CFsNode::s_nodehash[NODEHASHSIZE];

CFsNode* CFsNode::id_to_node(uint32_t id)
{
    uint32_t nodepos = NODEHASHPOS(id);
    for (CFsNode *p=s_nodehash[nodepos]; p ; p=p->next)
    {
        if (p->id == id) {
            return p;
        }
    }

    return NULL;
}

void CFsNode::dumpnodes()
{
    CFsNode *p;
    for (uint32_t i=0 ; i<NODEHASHSIZE; i++) {
        for (p=s_nodehash[i] ; p ; p=p->next) {
            p->dump();
        }
    }
}

void CFsNode::dump()
{
    uint32_t i,ch;
    STSIDRec *sIDPtr;

    char c='?';
    switch (type) {
    case TYPE_DIRECTORY:c='D';     break;
    case TYPE_SOCKET:   c='S';     break;
    case TYPE_FIFO:     c='F';     break;
    case TYPE_BLOCKDEV: c='B';     break;
    case TYPE_CHARDEV:  c='C';     break;
    case TYPE_SYMLINK:  c='L';     break;
    case TYPE_FILE:     c='-';     break;
    case TYPE_TRASH:    c='T';     break;
    case TYPE_RESERVED: c='R';     break;
    }

    printf("%c|i:%10"PRIu32"|#:%"PRIu8"|e:%1"PRIX16"|m:%04"PRIo16"|u:%10"PRIu32"|g:%10"PRIu32"|a:%10"PRIu32",m:%10"PRIu32",c:%10"PRIu32"|t:%10"PRIu32,
        c,id,goal,(uint16_t)(mode>>12),(uint16_t)(mode&0xFFF),uid,gid,atime,mtime,ctime,trashtime);

    if (type==TYPE_BLOCKDEV || type==TYPE_CHARDEV)
    {
        printf("|d:%5"PRIu32",%5"PRIu32"\n",data.devdata.rdev>>16,data.devdata.rdev&0xFFFF);
    } 
    else if (type==TYPE_SYMLINK)
    {
        printf("|p:%s\n", escape_name(data.sdata.pleng,data.sdata.path));
    }
    else if (type==TYPE_FILE || type==TYPE_TRASH || type==TYPE_RESERVED)
    {
        printf("|l:%20"PRIu64"|c:(",data.fdata.length);
        ch = 0;
        for (i=0 ; i<data.fdata.chunks ; i++) {
            if (data.fdata.chunktab[i]!=0) {
                ch=i+1;
            }
        }

        for (i=0 ; i<ch ; i++) {
            if (data.fdata.chunktab[i]!=0) {
                printf("%016"PRIX64,data.fdata.chunktab[i]);
            } else {
                printf("N");
            }
            if (i+1<ch) {
                printf(",");
            }
        }

        printf(")|r:(");
        for (sIDPtr=data.fdata.sessIDs ; sIDPtr ; sIDPtr=sIDPtr->next) {
            printf("%"PRIu32,sIDPtr->sessionid);
            if (sIDPtr->next) {
                printf(",");
            }
        }
        printf(")\n");
    } else {
        printf("\n");
    }
}

#ifndef METARESTORE
void CFsNode::checkfile(uint32_t chunkcount[11]) 
{
    uint32_t i;
    uint64_t chunkid;
    uint8_t count;

    memset(chunkcount, 0, sizeof(uint32_t)*11);
    for (i=0 ; i<this->data.fdata.chunks ; i++) {
        chunkid = this->data.fdata.chunktab[i];
        if (chunkid>0) {
            ChkMgr->chunk_get_validcopies(chunkid,&count);
            if (count>10) {
                count=10;
            }

            chunkcount[count]++;
        }
    }
}

void CFsNode::get_stats(STStatsRec *sr)
{
    uint32_t i,lastchunk,lastchunksize;
    switch (this->type) {
    case TYPE_DIRECTORY:
        *sr = *(this->data.ddata.stats);
        sr->inodes++;
        sr->dirs++;
        break;
    case TYPE_FILE:
    case TYPE_TRASH:
    case TYPE_RESERVED:
        sr->inodes = sr->files = 1;
        sr->dirs = sr->chunks = 0;
        sr->length = this->data.fdata.length;
        sr->size = 0;
        if (this->data.fdata.length>0) {
            lastchunk = (this->data.fdata.length-1)>>MFSCHUNKBITS;
            lastchunksize = ((((this->data.fdata.length-1)&MFSCHUNKMASK)+MFSBLOCKSIZE)&MFSBLOCKNEGMASK)+MFSHDRSIZE;
        } else {
            lastchunk = 0;
            lastchunksize = MFSHDRSIZE;
        }
        for (i=0 ; i<this->data.fdata.chunks ; i++) {
            if (this->data.fdata.chunktab[i]>0) {
                if (i<lastchunk) {
                    sr->size+=MFSCHUNKSIZE+MFSHDRSIZE;
                } else if (i==lastchunk) {
                    sr->size+=lastchunksize;
                }
                sr->chunks++;
            }
        }
        sr->realsize = sr->size * this->goal;
        break;
    case TYPE_SYMLINK:
        sr->inodes = 1;
        sr->files = sr->dirs = sr->chunks = 0;
        sr->length = this->data.sdata.pleng;
        sr->size =sr->realsize = 0;
        break;
    default:
        sr->inodes = 1;
        sr->files = sr->dirs = sr->chunks = 0;
        sr->length = sr->size = sr->realsize = 0;
        break;
    }
}

void CFsNode::sub_stats(STStatsRec *sr)
{
    CFsEdge *e;
    STStatsRec * psr = this->data.ddata.stats;

    psr->inodes -= sr->inodes;
    psr->dirs -= sr->dirs;
    psr->files -= sr->files;
    psr->chunks -= sr->chunks;
    psr->length -= sr->length;
    psr->size -= sr->size;
    psr->realsize -= sr->realsize;
    if (this != s_root) {
        for (e=this->parents ; e ; e=e->nextParent)
        {
            if(e->parent)
                e->parent->sub_stats(sr);
        }
    }
}

void CFsNode::add_stats(STStatsRec *sr)
{
    CFsEdge *e;
    STStatsRec *psr = this->data.ddata.stats;

    psr->inodes += sr->inodes;
    psr->dirs += sr->dirs;
    psr->files += sr->files;
    psr->chunks += sr->chunks;
    psr->length += sr->length;
    psr->size += sr->size;
    psr->realsize += sr->realsize;

    if (this != s_root) {
        for (e=this->parents ; e ; e=e->nextParent) {
            if(e->parent)
                e->parent->add_stats(sr);
        }
    }
}

void CFsNode::add_sub_stats(STStatsRec *newsr,STStatsRec *prevsr)
{
    STStatsRec sr;
    sr.inodes = newsr->inodes - prevsr->inodes;
    sr.dirs = newsr->dirs - prevsr->dirs;
    sr.files = newsr->files - prevsr->files;
    sr.chunks = newsr->chunks - prevsr->chunks;
    sr.length = newsr->length - prevsr->length;
    sr.size = newsr->size - prevsr->size;
    sr.realsize = newsr->realsize - prevsr->realsize;

    this->add_stats(&sr);
}

#endif

uint32_t CFsNode::getdir_size(uint8_t withattr) 
{
    uint32_t result = ((withattr)?40:6)*2+3;	// for '.' and '..'
    for (CFsEdge *e = this->data.ddata.children ; e ; e=e->nextChild) {
        result+=((withattr)?40:6)+e->nleng;
    }

    return result;
}

uint32_t CFsNode::getdirpath_size(uint32_t inode)
{
    CFsNode *node = CFsNode::id_to_node(inode);
    if (node) {
        if (node->type!=TYPE_DIRECTORY) {
            return 15; // "(not directory)"
        } else {
            return 1+node->parents->get_path_size();
        }
    } else {
        return 11; // "(not found)"
    }
    return 0;	// unreachable
}

void CFsNode::getdirpath_data(uint32_t inode,uint8_t *buff,uint32_t size)
{
    CFsNode *node = CFsNode::id_to_node(inode);
    if (node) {
        if (node->type!=TYPE_DIRECTORY) {
            if (size>=15) {
                memcpy(buff,"(not directory)",15);
                return;
            }
        } else {
            if (size>0) {
                buff[0]='/';
                node->parents->get_path_data(buff+1,size-1);
                return;
            }
        }
    } else {
        if (size>=11) {
            memcpy(buff,"(not found)",11);
            return;
        }
    }
}

void CFsNode::changefilegoal(uint8_t g)
{
#ifndef METARESTORE
    STStatsRec psr,nsr;
    CFsEdge *e;

    this->get_stats(&psr);
    nsr = psr;
    nsr.realsize = g * nsr.size;
    for (e=parents ; e ; e=e->nextParent)
    {
        if(e->parent)
            e->parent->add_sub_stats(&nsr,&psr);
    }
#endif

    for (uint32_t i=0 ; i<data.fdata.chunks ; i++) {
        if (data.fdata.chunktab[i]>0) {
            ChkMgr->chunk_change_file(data.fdata.chunktab[i], goal, g);
        }
    }

    this->goal = g;
}

char* CFsNode::escape_name(uint32_t nleng,const uint8_t *name)
{
    static char *escname[2]={NULL,NULL};
    static uint32_t escnamesize[2]={0,0};
    static uint8_t buffid=0;

    char *currescname=NULL;
    uint8_t c;
    buffid = 1-buffid;
    uint32_t i = nleng*3+1;

    if (i>escnamesize[buffid] || i==0)
    {
        escnamesize[buffid] = ((i/1000)+1)*1000;
        if (escname[buffid]!=NULL) {
            free(escname[buffid]);
        }

        escname[buffid] = (char*)malloc(escnamesize[buffid]);
        passert(escname[buffid]);
    }

    i = 0;
    currescname = escname[buffid];
    passert(currescname);
    while (nleng>0) {
        c = *name;
        if (c<32 || c>=127 || c==',' || c=='%' || c=='(' || c==')') {
            currescname[i++]='%';
            currescname[i++]="0123456789ABCDEF"[(c>>4)&0xF];
            currescname[i++]="0123456789ABCDEF"[c&0xF];
        } else {
            currescname[i++]=c;
        }
        name++;
        nleng--;
    }
    currescname[i]=0;

    return currescname;
}

int CFsNode::name_check(uint32_t nleng,const uint8_t *name)
{
    if (nleng==0 || nleng>MAXFNAMELENG) {
        return -1;
    }
    if (name[0]=='.') {
        if (nleng==1) {
            return -1;
        }
        if (nleng==2 && name[1]=='.') {
            return -1;
        }
    }
    for (uint32_t i=0 ; i<nleng ; i++) {
        if (name[i]=='\0' || name[i]=='/') {
            return -1;
        }
    }
    return 0;
}

CFsQuota* CFsNode::new_quotanode()
{
    CFsQuota *qn = new CFsQuota();
    passert(qn);

    qn->next = CFsQuota::s_quotaHead;
    if (qn->next) {
        qn->next->prev = &(qn->next);
    }

    qn->prev = &(CFsQuota::s_quotaHead);
    CFsQuota::s_quotaHead = qn;
    qn->node = this;
    this->data.ddata.quota = qn;

    return qn;
}

void CFsNode::delete_quotanode()
{
    CFsQuota *qn = this->data.ddata.quota;
    if (qn) {
        *(qn->prev) = qn->next;
        if (qn->next) {
            qn->next->prev = qn->prev;
        }

        delete qn;
        qn = NULL;
        this->data.ddata.quota = NULL;
    }
}

uint8_t CFsNode::test_quota() 
{
    CFsEdge *e;
    if (type==TYPE_DIRECTORY 
        && data.ddata.quota 
        && data.ddata.quota->exceeded)
    {
        return 1;
    }

    if (this!=s_root)
    {
        for (e=parents ; e ; e=e->nextParent)
        {
            if (e->parent && e->parent->test_quota()) {
                return 1;
            }
        }
    }

    return 0;
}

void CFsNode::set_length(uint64_t length)
{
    uint32_t i,chunks;
    uint64_t chunkid;
#ifndef METARESTORE
    STStatsRec psr,nsr;
    this->get_stats(&psr);
#endif
    if (this->type==TYPE_TRASH) {
        CFileSysMgr::s_trashspace -= this->data.fdata.length;
        CFileSysMgr::s_trashspace += length;
    } else if (this->type==TYPE_RESERVED) {
        CFileSysMgr::s_reservedspace -= this->data.fdata.length;
        CFileSysMgr::s_reservedspace += length;
    }

    this->data.fdata.length = length;
    if (length>0) {
        chunks = ((length-1)>>MFSCHUNKBITS)+1;
    } else {
        chunks = 0;
    }

    for (i=chunks ; i<this->data.fdata.chunks ; i++) {
        chunkid = this->data.fdata.chunktab[i];
        if (chunkid>0) {
            if (ChkMgr->chunk_delete_file(chunkid,this->goal)!=STATUS_OK) {
                syslog(LOG_ERR,"structure error - chunk %016"PRIX64" not found (inode: %"PRIu32" ; index: %"PRIu32")",chunkid,this->id,i);
            }
        }
        this->data.fdata.chunktab[i]=0;
    }

    if (chunks>0) {
        if (chunks<this->data.fdata.chunks && this->data.fdata.chunktab) {
            this->data.fdata.chunktab = (uint64_t*)realloc(this->data.fdata.chunktab,sizeof(uint64_t)*chunks);
            passert(this->data.fdata.chunktab);
            this->data.fdata.chunks = chunks;
        }
    } else {
        if (this->data.fdata.chunks>0 && this->data.fdata.chunktab) {
            free(this->data.fdata.chunktab);
            this->data.fdata.chunktab = NULL;
            this->data.fdata.chunks = 0;
        }
    }

#ifndef METARESTORE
    this->get_stats(&nsr);
    for (CFsEdge *e=this->parents ; e ; e=e->nextParent) {
        if(e->parent)
            e->parent->add_sub_stats(&nsr,&psr);
    }
#endif
}

uint8_t CFsNode::nameisused(uint16_t nleng,const uint8_t *name) 
{
    CFsEdge *ei;
#ifdef EDGEHASH
    if (this->data.ddata.elements>LOOKUPNOHASHLIMIT) {
        ei = CFsEdge::s_edgehash[EDGEHASHPOS(fsnodes_hash(this->id,nleng,name))];
        while (ei) {
            if (ei->parent==this && nleng==ei->nleng && memcmp((char*)(ei->name),(char*)name,nleng)==0) {
                return 1;
            }
            ei = ei->next;
        }
    } else {
        ei = this->data.ddata.children;
        while (ei) {
            if (nleng==ei->nleng && memcmp((char*)(ei->name),(char*)name,nleng)==0) {
                return 1;
            }
            ei = ei->nextChild;
        }
    }
#else
    ei = this->data.ddata.children;
    while (ei) {
        if (nleng==ei->nleng && memcmp((char*)(ei->name),(char*)name,nleng)==0) {
            return 1;
        }
        ei = ei->nextChild;
    }
#endif
    return 0;
}

CFsEdge* CFsNode::lookup(uint16_t nleng,const uint8_t *name)
{
    CFsEdge *ei;
    if (this->type!=TYPE_DIRECTORY) {
        return NULL;
    }
#ifdef EDGEHASH
    if (this->data.ddata.elements>LOOKUPNOHASHLIMIT) {
        ei = CFsEdge::s_edgehash[EDGEHASHPOS(fsnodes_hash(this->id,nleng,name))];
        while (ei) {
            if (ei->parent==this && nleng==ei->nleng && memcmp((char*)(ei->name),(char*)name,nleng)==0) {
                return ei;
            }
            ei = ei->next;
        }
    } else {
        ei = this->data.ddata.children;
        while (ei) {
            if (nleng==ei->nleng && memcmp((char*)(ei->name),(char*)name,nleng)==0) {
                return ei;
            }
            ei = ei->nextChild;
        }
    }
#else
    ei = this->data.ddata.children;
    while (ei) {
        if (nleng==ei->nleng && memcmp((char*)(ei->name),(char*)name,nleng)==0) {
            return ei;
        }
        ei = ei->nextChild;
    }
#endif
    return NULL;
}

void CFsNode::link_edge(uint32_t ts,
                        CFsNode *parent,CFsNode *child,
                        uint16_t nleng,const uint8_t *name)
{
    CFsEdge::new_edge(parent, child, nleng, name);
#ifndef METARESTORE
    STStatsRec sr;
    child->get_stats(&sr);
    parent->add_stats(&sr);
#endif
    if (ts>0) {
        parent->mtime = parent->ctime = ts;
        child->ctime = ts;
    }
}

void CFsNode::unlink_edge(uint32_t ts,CFsEdge *e)
{
    uint16_t pleng=0;
    uint8_t *path=NULL;

    CFsNode *child = e->child;
    if (child->parents->nextParent==NULL) { // last link
        if (child->type==TYPE_FILE 
            && (child->trashtime>0 || child->data.fdata.sessIDs!=NULL))
        {  
            e->get_path(&pleng,&path);
        }
    }

    e->remove_edge(ts);
    if (child->parents==NULL) {	// last link
        if (child->type == TYPE_FILE) {
            if (child->trashtime>0) {
                child->type = TYPE_TRASH;
                child->ctime = ts;
                e = CFsEdge::new_edge(TYPE_TRASH, pleng, path, child);
            } else if (child->data.fdata.sessIDs!=NULL) {
                child->type = TYPE_RESERVED;
                e = CFsEdge::new_edge(TYPE_RESERVED, pleng, path, child);
            } else {
                if (path) { // always should be NULL
                    free(path);
                }
                child->release_node(ts);
            }
        } else {
            if (path) { // always should be NULL
                free(path);
            }
            child->release_node(ts);
        }
    } else if (path) { // always should be NULL
        free(path);
    }
}

CFsNode* CFsNode::create_node(uint32_t ts,CFsNode* node,
                              uint16_t nleng,const uint8_t *name,
                              uint8_t type,uint16_t mode,
                              uint32_t uid,uint32_t gid,
                              uint8_t copysgid) 
{
    uint32_t nodepos;
    CFsNode *p = (CFsNode*)malloc(sizeof(CFsNode));
    passert(p);
    CFileSysMgr::s_nodes++;
    if (type==TYPE_DIRECTORY) {
        CFileSysMgr::s_dirnodes++;
    }
    if (type==TYPE_FILE) {
        CFileSysMgr::s_filenodes++;
    }

    p->id = CFileIDMgr::getInstance()->get_next_id();
    p->type = type;
    p->ctime = p->mtime = p->atime = ts;
    if (type==TYPE_DIRECTORY || type==TYPE_FILE) {
        p->goal = node->goal;
        p->trashtime = node->trashtime;
    } else {
        p->goal = DEFAULT_GOAL;
        p->trashtime = DEFAULT_TRASHTIME;
    }

    if (type==TYPE_DIRECTORY) {
        p->mode = (mode&07777) | (node->mode&0xF000);
    } else {
        p->mode = (mode&07777) | (node->mode&(0xF000&(~(EATTR_NOECACHE<<12))));
    }

    p->uid = uid;
    if ((node->mode&02000)==02000) {	// set gid flag is set in the parent directory ?
        p->gid = node->gid;
        if (copysgid && type==TYPE_DIRECTORY) {
            p->mode |= 02000;
        }
    } else {
        p->gid = gid;
    }

    switch (type)
    {
    case TYPE_DIRECTORY:
        {
#ifndef METARESTORE
            STStatsRec *sr = (STStatsRec*)malloc(sizeof(STStatsRec));
            passert(sr);
            memset(sr,0,sizeof(STStatsRec));
            p->data.ddata.stats = sr;
#endif
            p->data.ddata.quota = NULL;
            p->data.ddata.children = NULL;
            p->data.ddata.nlink = 2;
            p->data.ddata.elements = 0;
        }
        break;
    case TYPE_FILE:
        p->data.fdata.length = 0;
        p->data.fdata.chunks = 0;
        p->data.fdata.chunktab = NULL;
        p->data.fdata.sessIDs = NULL;
        break;
    case TYPE_SYMLINK:
        p->data.sdata.pleng = 0;
        p->data.sdata.path = NULL;
        break;
    case TYPE_BLOCKDEV:
    case TYPE_CHARDEV:
        p->data.devdata.rdev = 0;
    }

    p->parents = NULL;
    nodepos = NODEHASHPOS(p->id);
    p->next = s_nodehash[nodepos];
    s_nodehash[nodepos] = p;
    link_edge(ts,node,p,nleng,name);

    return p;
}

void CFsNode::release_node(uint32_t ts) 
{
    if (this->parents!=NULL) {
        return;
    }

    // remove from idhash
    uint32_t nodepos = NODEHASHPOS(this->id);
    CFsNode **ptr = &(CFsNode::s_nodehash[nodepos]);
    while (*ptr) {
        if (*ptr==this) {
            *ptr=this->next;
            break;
        }
        ptr = &((*ptr)->next);
    }

    // and free
    CFileSysMgr::s_nodes--;
    if (this->type==TYPE_DIRECTORY) {
        CFileSysMgr::s_dirnodes--;
        this->delete_quotanode();
#ifndef METARESTORE
        free(this->data.ddata.stats);
#endif
    }

    if (this->type==TYPE_FILE || this->type==TYPE_TRASH || this->type==TYPE_RESERVED) {
        uint32_t i;
        uint64_t chunkid;
        CFileSysMgr::s_filenodes--;
        for (i=0 ; i<this->data.fdata.chunks ; i++) {
            chunkid = this->data.fdata.chunktab[i];
            if (chunkid>0) {
                if (ChkMgr->chunk_delete_file(chunkid,this->goal)!=STATUS_OK) {
                    syslog(LOG_ERR,"structure error - chunk %016"PRIX64" not found (inode: %"PRIu32" ; index: %"PRIu32")",chunkid,this->id,i);
                }
            }
        }
        if (this->data.fdata.chunktab!=NULL) {
            free(this->data.fdata.chunktab);
        }
    }

    if (this->type==TYPE_SYMLINK) {
        free(this->data.sdata.path);
    }

    CFileIDMgr::getInstance()->free_id(this->id,ts);
    CFsXAttrNode::release(this->id);

#ifndef METARESTORE
    dcm_modify(this->id,0);
#endif

    free(this);
}

