#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <sys/stat.h>
#include <errno.h>

#ifndef METARESTORE
#include "ChunkCtrl.h"
#endif

#include "ClientConn.h"
#include "ChunkMgr.h"
#include "ChunkJob.h"
#include "FileIDMgr.h"
#include "FileSysOpr.h"
#include "FileSysMgr.h"

#ifndef METARESTORE
#include "cfg.h"
#endif

#define MAX_INDEX 0x7FFFFFFF

#ifndef METARESTORE
typedef struct _bstnode {
    uint32_t val,count;
    struct _bstnode *left,*right;
} bstnode;
#endif

#ifndef METARESTORE

static uint32_t BackMetaCopies;

#define MSGBUFFSIZE 1000000
#define ERRORS_LOG_MAX 500

static uint32_t fsinfo_files=0;
static uint32_t fsinfo_ugfiles=0;
static uint32_t fsinfo_mfiles=0;
static uint32_t fsinfo_chunks=0;
static uint32_t fsinfo_ugchunks=0;
static uint32_t fsinfo_mchunks=0;
static char *fsinfo_msgbuff=NULL;
static uint32_t fsinfo_msgbuffleng=0;
static uint32_t fsinfo_loopstart=0;
static uint32_t fsinfo_loopend=0;

static uint32_t test_start_time;

#define stats_statfs CFileSysMgr::stats_all[0]
#define stats_getattr CFileSysMgr::stats_all[1]
#define stats_setattr CFileSysMgr::stats_all[2]
#define stats_lookup CFileSysMgr::stats_all[3]
#define stats_mkdir CFileSysMgr::stats_all[4]
#define stats_rmdir CFileSysMgr::stats_all[5]
#define stats_symlink CFileSysMgr::stats_all[6]
#define stats_readlink CFileSysMgr::stats_all[7]
#define stats_mknod CFileSysMgr::stats_all[8]
#define stats_unlink CFileSysMgr::stats_all[9]
#define stats_rename CFileSysMgr::stats_all[10]
#define stats_link CFileSysMgr::stats_all[11]
#define stats_readdir CFileSysMgr::stats_all[12]
#define stats_open CFileSysMgr::stats_all[13]
#define stats_read CFileSysMgr::stats_all[14]
#define stats_write CFileSysMgr::stats_all[15]

#endif

/* xattr */
static inline int xattr_namecheck(uint8_t anleng,const uint8_t *attrname)
{
    for (uint32_t i=0 ; i<anleng ; i++) {
        if (attrname[i]=='\0') {
            return -1;
        }
    }

    return 0;
}

// returns 1 only if f is ancestor of p
static inline int fsnodes_isancestor(CFsNode *f,CFsNode *p) 
{
    for (CFsEdge *e=p->parents ; e ; e=e->nextParent) {	// check all parents of 'p' because 'p' can be any object, so it can be hardlinked
        p=e->parent;	// warning !!! since this point 'p' is used as temporary variable
        while (p) {
            if (f==p) {
                return 1;
            }
            if (p->parents) {
                p = p->parents->parent;	// here 'p' is always a directory so it should have only one parent
            } else {
                p = NULL;
            }
        }
    }

    return 0;
}

#ifndef METARESTORE

static inline void fsnodes_fill_attr(CFsNode *node,CFsNode *parent,
                                     uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                                     uint8_t sesflags,uint8_t attr[35])
{
    (void)sesflags;
    uint8_t *ptr = attr;
    if (node->type==TYPE_TRASH || node->type==TYPE_RESERVED) {
        put8bit(&ptr,TYPE_FILE);
    } else {
        put8bit(&ptr,node->type);
    }

    uint16_t mode = node->mode&07777;
    if (parent) {
        if (parent->mode&(EATTR_NOECACHE<<12)) {
            mode |= (MATTR_NOECACHE<<12);
        }
    }

    if ((node->mode&((EATTR_NOOWNER|EATTR_NOACACHE)<<12)) || (sesflags&SESFLAG_MAPALL)) {
        mode |= (MATTR_NOACACHE<<12);
    }
    if ((node->mode&(EATTR_NODATACACHE<<12))==0) {
        mode |= (MATTR_ALLOWDATACACHE<<12);
    }
    put16bit(&ptr,mode);
    if ((node->mode&(EATTR_NOOWNER<<12)) && uid!=0) {
        if (sesflags&SESFLAG_MAPALL) {
            put32bit(&ptr,auid);
            put32bit(&ptr,agid);
        } else {
            put32bit(&ptr,uid);
            put32bit(&ptr,gid);
        }
    } else {
        if (sesflags&SESFLAG_MAPALL && auid!=0) {
            if (node->uid==uid) {
                put32bit(&ptr,auid);
            } else {
                put32bit(&ptr,0);
            }
            if (node->gid==gid) {
                put32bit(&ptr,agid);
            } else {
                put32bit(&ptr,0);
            }
        } else {
            put32bit(&ptr,node->uid);
            put32bit(&ptr,node->gid);
        }
    }
    put32bit(&ptr,node->atime);
    put32bit(&ptr,node->mtime);
    put32bit(&ptr,node->ctime);

    uint32_t nlink = 0;
    for (CFsEdge *e=node->parents ; e ; e=e->nextParent) {
        nlink++;
    }

    switch (node->type) {
    case TYPE_FILE:
    case TYPE_TRASH:
    case TYPE_RESERVED:
        put32bit(&ptr,nlink);
        put64bit(&ptr,node->data.fdata.length);
        break;
    case TYPE_DIRECTORY:
        put32bit(&ptr,node->data.ddata.nlink);
        put64bit(&ptr,node->data.ddata.stats->length>>30);	// Rescale length to GB (reduces size to 32-bit length)
        break;
    case TYPE_SYMLINK:
        put32bit(&ptr,nlink);
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        put32bit(&ptr,node->data.sdata.pleng);
        break;
    case TYPE_BLOCKDEV:
    case TYPE_CHARDEV:
        put32bit(&ptr,nlink);
        put32bit(&ptr,node->data.devdata.rdev);
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        break;
    default:
        put32bit(&ptr,nlink);
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
        *ptr++=0;
    }
}

static inline void fsnodes_getdirdata(uint32_t rootinode,
                                      uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                                      uint8_t sesflags,CFsNode *p,uint8_t *dbuff,uint8_t withattr)
{
    // '.' - self
    dbuff[0]=1;
    dbuff[1]='.';
    dbuff+=2;
    if (p->id!=rootinode) {
        put32bit(&dbuff,p->id);
    } else {
        put32bit(&dbuff,MFS_ROOT_ID);
    }
    if (withattr) {
        fsnodes_fill_attr(p,p,uid,gid,auid,agid,sesflags,dbuff);
        dbuff+=35;
    } else {
        put8bit(&dbuff,TYPE_DIRECTORY);
    }
    // '..' - parent
    dbuff[0]=2;
    dbuff[1]='.';
    dbuff[2]='.';
    dbuff+=3;
    if (p->id==rootinode) { // root node should returns self as its parent
        put32bit(&dbuff,MFS_ROOT_ID);
        if (withattr) {
            fsnodes_fill_attr(p,p,uid,gid,auid,agid,sesflags,dbuff);
            dbuff+=35;
        } else {
            put8bit(&dbuff,TYPE_DIRECTORY);
        }
    } else {
        if (p->parents && p->parents->parent->id!=rootinode) {
            put32bit(&dbuff,p->parents->parent->id);
        } else {
            put32bit(&dbuff,MFS_ROOT_ID);
        }

        if (withattr) {
            if (p->parents) {
                fsnodes_fill_attr(p->parents->parent,p,uid,gid,auid,agid,sesflags,dbuff);
            } else {
                if (rootinode==MFS_ROOT_ID) {
                    fsnodes_fill_attr(CFsNode::s_root,p,uid,gid,auid,agid,sesflags,dbuff);
                } else {
                    CFsNode *rn = CFsNode::id_to_node(rootinode);
                    if (rn) {	// it should be always true because it's checked before, but better check than sorry
                        fsnodes_fill_attr(rn,p,uid,gid,auid,agid,sesflags,dbuff);
                    } else {
                        memset(dbuff,0,35);
                    }
                }
            }
            dbuff+=35;
        } else {
            put8bit(&dbuff,TYPE_DIRECTORY);
        }
    }

    // entries
    for (CFsEdge *e = p->data.ddata.children ; e ; e=e->nextChild) {
        dbuff[0]=e->nleng;
        dbuff++;
        memcpy(dbuff,e->name,e->nleng);
        dbuff+=e->nleng;
        put32bit(&dbuff,e->child->id);
        if (withattr) {
            fsnodes_fill_attr(e->child,p,uid,gid,auid,agid,sesflags,dbuff);
            dbuff+=35;
        } else {
            put8bit(&dbuff,e->child->type);
        }
    }
}

#endif

static inline uint8_t fsnodes_appendchunks(uint32_t ts,CFsNode *dstobj,CFsNode *srcobj)
{
    uint64_t chunkid,length;
    uint32_t i;
#ifndef METARESTORE
    STStatsRec psr,nsr;
    CFsEdge *e;
#endif

    uint32_t srcChunks=0;
    for (i=0 ; i<srcobj->data.fdata.chunks ; i++) {
        if (srcobj->data.fdata.chunktab[i]!=0) {
            srcChunks = i+1;
        }
    }
    if (srcChunks==0) {
        return STATUS_OK;
    }

    uint32_t dstChunks=0;
    for (i=0 ; i<dstobj->data.fdata.chunks ; i++) {
        if (dstobj->data.fdata.chunktab[i]!=0) {
            dstChunks = i+1;
        }
    }

    i = srcChunks+dstChunks-1;	// last new chunk pos
    if (i>MAX_INDEX) {	// chain too long
        return ERROR_INDEXTOOBIG;
    }
#ifndef METARESTORE
    dstobj->get_stats(&psr);
#endif

    if (i>=dstobj->data.fdata.chunks) {
        uint32_t newsize;
        if (i<8) {
            newsize=i+1;
        } else if (i<64) {
            newsize=(i&0xFFFFFFF8)+8;
        } else {
            newsize = (i&0xFFFFFFC0)+64;
        }

        if (dstobj->data.fdata.chunktab==NULL) {
            dstobj->data.fdata.chunktab = (uint64_t*)malloc(sizeof(uint64_t)*newsize);
        } else {
            dstobj->data.fdata.chunktab = (uint64_t*)realloc(dstobj->data.fdata.chunktab,sizeof(uint64_t)*newsize);
        }
        passert(dstobj->data.fdata.chunktab);
        for (i=dstobj->data.fdata.chunks ; i<newsize ; i++) {
            dstobj->data.fdata.chunktab[i]=0;
        }
        dstobj->data.fdata.chunks = newsize;
    }

    for (i=0 ; i<srcChunks ; i++) {
        chunkid = srcobj->data.fdata.chunktab[i];
        dstobj->data.fdata.chunktab[i+dstChunks] = chunkid;
        if (chunkid>0) {
            if (ChkMgr->chunk_add_file(chunkid,dstobj->goal)!=STATUS_OK) {
                syslog(LOG_ERR,"structure error - chunk %016"PRIX64" not found (inode: %"PRIu32" ; index: %"PRIu32")",chunkid,srcobj->id,i);
            }
        }
    }

    length = (((uint64_t)dstChunks)<<MFSCHUNKBITS)+srcobj->data.fdata.length;
    if (dstobj->type==TYPE_TRASH) {
        CFileSysMgr::s_trashspace -= dstobj->data.fdata.length;
        CFileSysMgr::s_trashspace += length;
    } else if (dstobj->type==TYPE_RESERVED) {
        CFileSysMgr::s_reservedspace -= dstobj->data.fdata.length;
        CFileSysMgr::s_reservedspace += length;
    }
    dstobj->data.fdata.length = length;

#ifndef METARESTORE
    dstobj->get_stats(&nsr);
    for (e=dstobj->parents ; e ; e=e->nextParent) {
        if(e->parent)
            e->parent->add_sub_stats(&nsr,&psr);
    }
#endif

#ifdef METARESTORE
    dstobj->mtime = ts;
    dstobj->atime = ts;
    srcobj->atime = ts;
#else /* ! METARESTORE */
    dstobj->mtime = ts;
    dstobj->atime = ts;
    if (srcobj->atime!=ts) {
        srcobj->atime = ts;
    }
#endif

    return STATUS_OK;
}

static inline int fsnodes_purge(uint32_t ts,CFsNode *p)
{
    CFsEdge *e = p->parents;
    if (p->type==TYPE_TRASH)
    {
        CFileSysMgr::s_trashspace -= p->data.fdata.length;
        CFileSysMgr::s_trashnodes--;
        if (p->data.fdata.sessIDs!=NULL) {
            p->type = TYPE_RESERVED;
            CFileSysMgr::s_reservedspace += p->data.fdata.length;
            CFileSysMgr::s_reservednodes++;
            *(e->prevChild) = e->nextChild;
            if (e->nextChild) {
                e->nextChild->prevChild = e->prevChild;
            }
            e->nextChild = CFsEdge::s_reserved;
            e->prevChild = &(CFsEdge::s_reserved);
            if (e->nextChild) {
                e->nextChild->prevChild = &(e->nextChild);
            }
            CFsEdge::s_reserved = e;
            return 0;
        } else {
            e->remove_edge(ts);
            p->release_node(ts);
            return 1;
        }
    } else if (p->type==TYPE_RESERVED) {
        CFileSysMgr::s_reservedspace -= p->data.fdata.length;
        CFileSysMgr::s_reservednodes--;
        e->remove_edge(ts);
        p->release_node(ts);
        return 1;
    }
    return -1;
}

static inline uint8_t fsnodes_undel(uint32_t ts,CFsNode *node)
{
    uint8_t newf;
    uint32_t i,partleng,dots;
    CFsEdge *e,*pe;
    CFsNode *p,*n;

    /* check path */
    e = node->parents;
    uint16_t pleng = e->nleng;
    const uint8_t *path = e->name;

    if (path==NULL) {
        return ERROR_CANTCREATEPATH;
    }
    while (*path=='/' && pleng>0) {
        path++;
        pleng--;
    }
    if (pleng==0) {
        return ERROR_CANTCREATEPATH;
    }

    partleng=0;
    dots=0;
    for (i=0 ; i<pleng ; i++) {
        if (path[i]==0) {	// incorrect name character
            return ERROR_CANTCREATEPATH;
        } else if (path[i]=='/') {
            if (partleng==0) {	// "//" in path
                return ERROR_CANTCREATEPATH;
            }
            if (partleng==dots && partleng<=2) {	// '.' or '..' in path
                return ERROR_CANTCREATEPATH;
            }
            partleng=0;
            dots=0;
        } else {
            if (path[i]=='.') {
                dots++;
            }
            partleng++;
            if (partleng>MAXFNAMELENG) {
                return ERROR_CANTCREATEPATH;
            }
        }
    }

    if (partleng==0) {	// last part canot be empty - it's the name of undeleted file
        return ERROR_CANTCREATEPATH;
    }
    if (partleng==dots && partleng<=2) {	// '.' or '..' in path
        return ERROR_CANTCREATEPATH;
    }

    /* create path */
    n = NULL;
    p = CFsNode::s_root;
    newf = 0;
    for (;;) {
#ifndef METARESTORE
        if (p->data.ddata.quota && p->data.ddata.quota->exceeded) {
            return ERROR_QUOTA;
        }
#endif
        partleng=0;
        while (path[partleng]!='/' && partleng<pleng) {
            partleng++;
        }
        if (partleng==pleng) {	// last name
            if (p->nameisused(partleng,path)) {
                return ERROR_EEXIST;
            }
            // remove from trash and link to new parent
            node->type = TYPE_FILE;
            node->ctime = ts;
            CFsNode::link_edge(ts,p,node,partleng,path);
            e->remove_edge(ts);
            CFileSysMgr::s_trashspace -= node->data.fdata.length;
            CFileSysMgr::s_trashnodes--;
            return STATUS_OK;
        } else {
            if (newf==0) {
                pe = p->lookup(partleng,path);
                if (pe==NULL) {
                    newf=1;
                } else {
                    n = pe->child;
                    if (n->type!=TYPE_DIRECTORY) {
                        return ERROR_CANTCREATEPATH;
                    }
                }
            }
            if (newf==1) {
                n = CFsNode::create_node(ts,p,partleng,path,TYPE_DIRECTORY,0755,0,0,0);
            }
            p = n;
        }
        path+=partleng+1;
        pleng-=partleng+1;
    }
}

#ifndef METARESTORE

static inline void fsnodes_getgoal_recursive(CFsNode *node,uint8_t gmode,uint32_t fgtab[10],uint32_t dgtab[10])
{
    CFsEdge *e;
    if (node->type==TYPE_FILE || node->type==TYPE_TRASH || node->type==TYPE_RESERVED)
    {
        if (node->goal>9) {
            syslog(LOG_WARNING,"inode %"PRIu32": goal>9 !!! - fixing",node->id);
            node->changefilegoal(9);
        } else if (node->goal<1) {
            syslog(LOG_WARNING,"inode %"PRIu32": goal<1 !!! - fixing",node->id);
            node->changefilegoal(1);
        }
        fgtab[node->goal]++;
    } else if (node->type==TYPE_DIRECTORY) {
        if (node->goal>9) {
            syslog(LOG_WARNING,"inode %"PRIu32": goal>9 !!! - fixing",node->id);
            node->goal=9;
        } else if (node->goal<1) {
            syslog(LOG_WARNING,"inode %"PRIu32": goal<1 !!! - fixing",node->id);
            node->goal=1;
        }
        dgtab[node->goal]++;
        if (gmode==GMODE_RECURSIVE) {
            for (e = node->data.ddata.children ; e ; e=e->nextChild) {
                fsnodes_getgoal_recursive(e->child,gmode,fgtab,dgtab);
            }
        }
    }
}

static inline void fsnodes_bst_add(bstnode **n,uint32_t val) {
    while (*n) {
        if (val<(*n)->val) {
            n = &((*n)->left);
        } else if (val>(*n)->val) {
            n = &((*n)->right);
        } else {
            (*n)->count++;
            return;
        }
    }

    (*n)=(bstnode*)malloc(sizeof(bstnode));
    passert(*n);
    (*n)->val = val;
    (*n)->count = 1;
    (*n)->left = NULL;
    (*n)->right = NULL;
}

static inline uint32_t fsnodes_bst_nodes(bstnode *n) {
    if (n) {
        return 1+fsnodes_bst_nodes(n->left)+fsnodes_bst_nodes(n->right);
    } else {
        return 0;
    }
}

static inline void fsnodes_bst_storedata(bstnode *n,uint8_t **ptr) {
    if (n) {
        fsnodes_bst_storedata(n->left,ptr);
        put32bit(&*ptr,n->val);
        put32bit(&*ptr,n->count);
        fsnodes_bst_storedata(n->right,ptr);
    }
}

static inline void fsnodes_bst_free(bstnode *n) {
    if (n) {
        fsnodes_bst_free(n->left);
        fsnodes_bst_free(n->right);
        free(n);
    }
}

static inline void fsnodes_gettrashtime_recursive(CFsNode *node,uint8_t gmode,bstnode **bstrootfiles,bstnode **bstrootdirs)
{
    if (node->type==TYPE_FILE || node->type==TYPE_TRASH || node->type==TYPE_RESERVED) {
        fsnodes_bst_add(bstrootfiles,node->trashtime);
    } else if (node->type==TYPE_DIRECTORY) {
        fsnodes_bst_add(bstrootdirs,node->trashtime);
        if (gmode==GMODE_RECURSIVE) {
            for (CFsEdge *e = node->data.ddata.children ; e ; e=e->nextChild) {
                fsnodes_gettrashtime_recursive(e->child,gmode,bstrootfiles,bstrootdirs);
            }
        }
    }
}

static inline void fsnodes_geteattr_recursive(CFsNode *node,uint8_t gmode,uint32_t feattrtab[16],uint32_t deattrtab[16])
{
    if (node->type!=TYPE_DIRECTORY) {
        feattrtab[(node->mode>>12)&(EATTR_NOOWNER|EATTR_NOACACHE|EATTR_NODATACACHE)]++;
    } else {
        deattrtab[(node->mode>>12)]++;
        if (gmode==GMODE_RECURSIVE) {
            for (CFsEdge *e = node->data.ddata.children ; e ; e=e->nextChild) {
                fsnodes_geteattr_recursive(e->child,gmode,feattrtab,deattrtab);
            }
        }
    }
}

#endif

#if VERSHEX>=0x010700
static inline void fsnodes_setgoal_recursive(CFsNode *node,uint32_t ts,uint32_t uid,uint8_t quota,uint8_t goal,uint8_t smode,uint32_t *sinodes,uint32_t *ncinodes,uint32_t *nsinodes,uint32_t *qeinodes) {
#else
static inline void fsnodes_setgoal_recursive(CFsNode *node,uint32_t ts,uint32_t uid,uint8_t goal,uint8_t smode,uint32_t *sinodes,uint32_t *ncinodes,uint32_t *nsinodes) {
#endif
    uint8_t set;

    if (node->type==TYPE_FILE || node->type==TYPE_DIRECTORY || node->type==TYPE_TRASH || node->type==TYPE_RESERVED) {
        if ((node->mode&(EATTR_NOOWNER<<12))==0 && uid!=0 && node->uid!=uid) {
            (*nsinodes)++;
        } else {
            set=0;
            switch (smode&SMODE_TMASK) {
            case SMODE_SET:
                if (node->goal!=goal) {
                    set=1;
                }
                break;
            case SMODE_INCREASE:
                if (node->goal<goal) {
                    set=1;
                }
                break;
            case SMODE_DECREASE:
                if (node->goal>goal) {
                    set=1;
                }
                break;
            }

            if (set) {
                if (node->type!=TYPE_DIRECTORY) {
#if VERSHEX>=0x010700
                    if (quota && goal>node->goal) {
                        (*qeinodes)++;
                    } else {
#endif
                        node->changefilegoal(goal);
                        (*sinodes)++;
#if VERSHEX>=0x010700
                    }
#endif
                } else {
                    node->goal=goal;
                    (*sinodes)++;
                }
                node->ctime = ts;
            } else {
                (*ncinodes)++;
            }
        }
        if (node->type==TYPE_DIRECTORY && (smode&SMODE_RMASK)) {
#if VERSHEX>=0x010700
            if (quota==0 && node->data.ddata.quota && node->data.ddata.quota->exceeded) {
                quota=1;
            }
#endif
            for (CFsEdge *e = node->data.ddata.children ; e ; e=e->nextChild) {
#if VERSHEX>=0x010700
                fsnodes_setgoal_recursive(e->child,ts,uid,quota,goal,smode,sinodes,ncinodes,nsinodes,qeinodes);
#else
                fsnodes_setgoal_recursive(e->child,ts,uid,goal,smode,sinodes,ncinodes,nsinodes);
#endif
            }
        }
    }
}

static inline void fsnodes_settrashtime_recursive(CFsNode *node,uint32_t ts,uint32_t uid,uint32_t trashtime,uint8_t smode,uint32_t *sinodes,uint32_t *ncinodes,uint32_t *nsinodes)
{
    uint8_t set;
    if (node->type==TYPE_FILE || node->type==TYPE_DIRECTORY || node->type==TYPE_TRASH || node->type==TYPE_RESERVED) {
        if ((node->mode&(EATTR_NOOWNER<<12))==0 && uid!=0 && node->uid!=uid) {
            (*nsinodes)++;
        } else {
            set=0;
            switch (smode&SMODE_TMASK)
            {
            case SMODE_SET:
                if (node->trashtime!=trashtime) {
                    node->trashtime=trashtime;
                    set=1;
                }
                break;
            case SMODE_INCREASE:
                if (node->trashtime<trashtime) {
                    node->trashtime=trashtime;
                    set=1;
                }
                break;
            case SMODE_DECREASE:
                if (node->trashtime>trashtime) {
                    node->trashtime=trashtime;
                    set=1;
                }
                break;
            }

            if (set) {
                (*sinodes)++;
                node->ctime = ts;
            } else {
                (*ncinodes)++;
            }
        }
        if (node->type==TYPE_DIRECTORY && (smode&SMODE_RMASK)) {
            for (CFsEdge *e = node->data.ddata.children ; e ; e=e->nextChild) {
                fsnodes_settrashtime_recursive(e->child,ts,uid,trashtime,smode,sinodes,ncinodes,nsinodes);
            }
        }
    }
}

static inline void fsnodes_seteattr_recursive(CFsNode *node,uint32_t ts,uint32_t uid,uint8_t eattr,uint8_t smode,uint32_t *sinodes,uint32_t *ncinodes,uint32_t *nsinodes)
{
    if ((node->mode&(EATTR_NOOWNER<<12))==0 && uid!=0 && node->uid!=uid) {
        (*nsinodes)++;
    } else {
        uint8_t seattr = eattr;
        if (node->type!=TYPE_DIRECTORY) {
            node->mode &= ~(EATTR_NOECACHE<<12);
            seattr &= ~(EATTR_NOECACHE);
        }

        uint8_t neweattr = (node->mode>>12);
        switch (smode&SMODE_TMASK) {
        case SMODE_SET:
            neweattr = seattr;
            break;
        case SMODE_INCREASE:
            neweattr |= seattr;
            break;
        case SMODE_DECREASE:
            neweattr &= ~seattr;
            break;
        }

        if (neweattr!=(node->mode>>12)) {
            node->mode = (node->mode&0xFFF) | (((uint16_t)neweattr)<<12);
            (*sinodes)++;
            node->ctime = ts;
        } else {
            (*ncinodes)++;
        }
    }
    if (node->type==TYPE_DIRECTORY && (smode&SMODE_RMASK)) {
        for (CFsEdge *e = node->data.ddata.children ; e ; e=e->nextChild) {
            fsnodes_seteattr_recursive(e->child,ts,uid,eattr,smode,sinodes,ncinodes,nsinodes);
        }
    }
}

static inline void fsnodes_snapshot(uint32_t ts,CFsNode *srcnode,CFsNode *parentnode,uint32_t nleng,const uint8_t *name)
{
    CFsEdge *e;
    CFsNode *dstnode;
    uint32_t i;
    uint64_t chunkid;
    if ((e=parentnode->lookup(nleng,name))) {
        dstnode = e->child;
        if (srcnode->type==TYPE_DIRECTORY) {
            for (e = srcnode->data.ddata.children ; e ; e=e->nextChild) {
                fsnodes_snapshot(ts,e->child,dstnode,e->nleng,e->name);
            }
        } else if (srcnode->type==TYPE_FILE) {
            uint8_t same;
            if (dstnode->data.fdata.length==srcnode->data.fdata.length && dstnode->data.fdata.chunks==srcnode->data.fdata.chunks) {
                same=1;
                for (i=0 ; i<srcnode->data.fdata.chunks && same ; i++) {
                    if (srcnode->data.fdata.chunktab[i]!=dstnode->data.fdata.chunktab[i]) {
                        same=0;
                    }
                }
            } else {
                same=0;
            }

            if (same==0) {
#ifndef METARESTORE
                STStatsRec psr,nsr;
#endif
                CFsNode::unlink_edge(ts,e);
                dstnode = CFsNode::create_node(ts,parentnode,nleng,name,TYPE_FILE,srcnode->mode,srcnode->uid,srcnode->gid,0);
#ifndef METARESTORE
                dstnode->get_stats(&psr);
#endif
                dstnode->goal = srcnode->goal;
                dstnode->trashtime = srcnode->trashtime;
                if (srcnode->data.fdata.chunks>0) {
                    dstnode->data.fdata.chunktab = (uint64_t*)malloc(sizeof(uint64_t)*(srcnode->data.fdata.chunks));
                    passert(dstnode->data.fdata.chunktab);
                    dstnode->data.fdata.chunks = srcnode->data.fdata.chunks;
                    for (i=0 ; i<srcnode->data.fdata.chunks ; i++) {
                        chunkid = srcnode->data.fdata.chunktab[i];
                        dstnode->data.fdata.chunktab[i] = chunkid;
                        if (chunkid>0) {
                            if (ChkMgr->chunk_add_file(chunkid,dstnode->goal)!=STATUS_OK) {
                                syslog(LOG_ERR,"structure error - chunk %016"PRIX64" not found (inode: %"PRIu32" ; index: %"PRIu32")",chunkid,srcnode->id,i);
                            }
                        }
                    }
                } else {
                    dstnode->data.fdata.chunktab = NULL;
                    dstnode->data.fdata.chunks = 0;
                }
                dstnode->data.fdata.length = srcnode->data.fdata.length;
#ifndef METARESTORE
                dstnode->get_stats(&nsr);
                parentnode->add_sub_stats(&nsr,&psr);
#endif
            }
        } else if (srcnode->type==TYPE_SYMLINK) {
#ifndef METARESTORE
            if (dstnode->data.sdata.pleng!=srcnode->data.sdata.pleng) {
                STStatsRec sr;
                memset(&sr,0,sizeof(STStatsRec));
                sr.length = dstnode->data.sdata.pleng-srcnode->data.sdata.pleng;
                parentnode->add_stats(&sr);
            }
#endif
            if (dstnode->data.sdata.path) {
                free(dstnode->data.sdata.path);
            }
            if (srcnode->data.sdata.pleng>0) {
                dstnode->data.sdata.path = (uint8_t*)malloc(srcnode->data.sdata.pleng);
                passert(dstnode->data.sdata.path);
                memcpy(dstnode->data.sdata.path,srcnode->data.sdata.path,srcnode->data.sdata.pleng);
                dstnode->data.sdata.pleng = srcnode->data.sdata.pleng;
            } else {
                dstnode->data.sdata.path=NULL;
                dstnode->data.sdata.pleng=0;
            }
        } else if (srcnode->type==TYPE_BLOCKDEV || srcnode->type==TYPE_CHARDEV) {
            dstnode->data.devdata.rdev = srcnode->data.devdata.rdev;
        }
        dstnode->mode = srcnode->mode;
        dstnode->uid = srcnode->uid;
        dstnode->gid = srcnode->gid;
        dstnode->atime = srcnode->atime;
        dstnode->mtime = srcnode->mtime;
        dstnode->ctime = ts;
    } else {
        if (srcnode->type==TYPE_FILE || srcnode->type==TYPE_DIRECTORY 
            || srcnode->type==TYPE_SYMLINK || srcnode->type==TYPE_BLOCKDEV
            || srcnode->type==TYPE_CHARDEV || srcnode->type==TYPE_SOCKET
            || srcnode->type==TYPE_FIFO) 
        {
#ifndef METARESTORE
            STStatsRec psr,nsr;
#endif
            dstnode = CFsNode::create_node(ts,parentnode,nleng,name,srcnode->type,srcnode->mode,srcnode->uid,srcnode->gid,0);
#ifndef METARESTORE
            dstnode->get_stats(&psr);
#endif
            dstnode->goal = srcnode->goal;
            dstnode->trashtime = srcnode->trashtime;
            dstnode->mode = srcnode->mode;
            dstnode->atime = srcnode->atime;
            dstnode->mtime = srcnode->mtime;
            if (srcnode->type==TYPE_DIRECTORY) {
                for (e = srcnode->data.ddata.children ; e ; e=e->nextChild) {
                    fsnodes_snapshot(ts,e->child,dstnode,e->nleng,e->name);
                }
            } else if (srcnode->type==TYPE_FILE) {
                if (srcnode->data.fdata.chunks>0) {
                    dstnode->data.fdata.chunktab = (uint64_t*)malloc(sizeof(uint64_t)*(srcnode->data.fdata.chunks));
                    passert(dstnode->data.fdata.chunktab);
                    dstnode->data.fdata.chunks = srcnode->data.fdata.chunks;
                    for (i=0 ; i<srcnode->data.fdata.chunks ; i++) {
                        chunkid = srcnode->data.fdata.chunktab[i];
                        dstnode->data.fdata.chunktab[i] = chunkid;
                        if (chunkid>0) {
                            if (ChkMgr->chunk_add_file(chunkid,dstnode->goal)!=STATUS_OK) {
                                syslog(LOG_ERR,"structure error - chunk %016"PRIX64" not found (inode: %"PRIu32" ; index: %"PRIu32")",chunkid,srcnode->id,i);
                            }
                        }
                    }
                } else {
                    dstnode->data.fdata.chunktab = NULL;
                    dstnode->data.fdata.chunks = 0;
                }
                dstnode->data.fdata.length = srcnode->data.fdata.length;
#ifndef METARESTORE
                dstnode->get_stats(&nsr);
                parentnode->add_sub_stats(&nsr,&psr);
#endif
            } else if (srcnode->type==TYPE_SYMLINK) {
                if (srcnode->data.sdata.pleng>0) {
                    dstnode->data.sdata.path =(uint8_t*)malloc(srcnode->data.sdata.pleng);
                    passert(dstnode->data.sdata.path);
                    memcpy(dstnode->data.sdata.path,srcnode->data.sdata.path,srcnode->data.sdata.pleng);
                    dstnode->data.sdata.pleng = srcnode->data.sdata.pleng;
                }
#ifndef METARESTORE
                dstnode->get_stats(&nsr);
                parentnode->add_sub_stats(&nsr,&psr);
#endif
            } else if (srcnode->type==TYPE_BLOCKDEV || srcnode->type==TYPE_CHARDEV) {
                dstnode->data.devdata.rdev = srcnode->data.devdata.rdev;
            }
        }
    }
}

static inline uint8_t fsnodes_snapshot_test(CFsNode *origsrcnode,CFsNode *srcnode,CFsNode *parentnode,
                                            uint32_t nleng,const uint8_t *name,
                                            uint8_t canoverwrite) 
{
    CFsEdge *e=parentnode->lookup(nleng,name);
    if (e)
    {
        CFsNode *dstnode = e->child;
        if (dstnode==origsrcnode) {
            return ERROR_EINVAL;
        }
        if (dstnode->type!=srcnode->type) {
            return ERROR_EPERM;
        }
        if (srcnode->type==TYPE_TRASH || srcnode->type==TYPE_RESERVED) {
            return ERROR_EPERM;
        }

        if (srcnode->type==TYPE_DIRECTORY) {
            for (e = srcnode->data.ddata.children ; e ; e=e->nextChild) {
                uint8_t status = fsnodes_snapshot_test(origsrcnode,e->child,dstnode,e->nleng,e->name,canoverwrite);
                if (status!=STATUS_OK) {
                    return status;
                }
            }
        } else if (canoverwrite==0) {
            return ERROR_EEXIST;
        }
    }

    return STATUS_OK;
}

#ifndef METARESTORE
static inline int fsnodes_access(CFsNode *node,uint32_t uid,uint32_t gid,uint8_t modemask,uint8_t sesflags) {
    if (uid==0) {
        return 1;
    }

    uint8_t nodemode;
    if (uid==node->uid || (node->mode&(EATTR_NOOWNER<<12))) {
        nodemode = ((node->mode)>>6) & 7;
    } else if (sesflags&SESFLAG_IGNOREGID) {
        nodemode = (((node->mode)>>3) | (node->mode)) & 7;
    } else if (gid==node->gid) {
        nodemode = ((node->mode)>>3) & 7;
    } else {
        nodemode = (node->mode & 7);
    }

    if ((nodemode & modemask) == modemask) {
        return 1;
    }
    return 0;
}

static inline int fsnodes_sticky_access(CFsNode *parent,CFsNode *node,uint32_t uid)
{
    if (uid==0 || (parent->mode&01000)==0) {	// super user or sticky bit is not set
        return 1;
    }
    if (uid==parent->uid || (parent->mode&(EATTR_NOOWNER<<12)) 
        || uid==node->uid || (node->mode&(EATTR_NOOWNER<<12)))
    {
        return 1;
    }

    return 0;
}

#endif
/* master <-> fuse operations */

#ifdef METARESTORE
uint8_t fs_access(uint32_t ts,uint32_t inode) {
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }

    p->atime = ts;
    CFileSysMgr::s_MetaVersion++;
    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint8_t fs_readreserved_size(uint32_t rootinode,uint8_t sesflags,uint32_t *dbuffsize) {
    if (rootinode!=0) {
        return ERROR_EPERM;
    }
    (void)sesflags;
    *dbuffsize = CFsEdge::s_reserved->get_detached_size();
    return STATUS_OK;
}

void fs_readreserved_data(uint32_t rootinode,uint8_t sesflags,uint8_t *dbuff) {
    (void)rootinode;
    (void)sesflags;
    CFsEdge::s_reserved->get_detached_data(dbuff);
}

uint8_t fs_readtrash_size(uint32_t rootinode,uint8_t sesflags,uint32_t *dbuffsize) {
    if (rootinode!=0) {
        return ERROR_EPERM;
    }
    (void)sesflags;
    *dbuffsize = CFsEdge::s_trash->get_detached_size();
    return STATUS_OK;
}

void fs_readtrash_data(uint32_t rootinode,uint8_t sesflags,uint8_t *dbuff) {
    (void)rootinode;
    (void)sesflags;
    CFsEdge::s_trash->get_detached_data(dbuff);
}

/* common procedure for trash and reserved files */
uint8_t fs_getdetachedattr(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint8_t attr[35],uint8_t dtype)
{
    memset(attr,0,35);
    if (rootinode!=0) {
        return ERROR_EPERM;
    }
    (void)sesflags;
    if (!DTYPE_ISVALID(dtype)) {
        return ERROR_EINVAL;
    }

    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_ENOENT;
    }
    if (dtype==DTYPE_TRASH && p->type==TYPE_RESERVED) {
        return ERROR_ENOENT;
    }
    if (dtype==DTYPE_RESERVED && p->type==TYPE_TRASH) {
        return ERROR_ENOENT;
    }
    fsnodes_fill_attr(p,NULL,p->uid,p->gid,p->uid,p->gid,sesflags,attr);
    return STATUS_OK;
}

uint8_t fs_gettrashpath(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint32_t *pleng,uint8_t **path) {
    *pleng = 0;
    *path = NULL;
    if (rootinode!=0) {
        return ERROR_EPERM;
    }
    (void)sesflags;
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_TRASH) {
        return ERROR_ENOENT;
    }
    *pleng = p->parents->nleng;
    *path = p->parents->name;
    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint8_t fs_settrashpath(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint32_t pleng,const uint8_t *path) {
#else
uint8_t fs_setpath(uint32_t inode,const uint8_t *path) {
#endif

#ifdef METARESTORE
    uint32_t pleng = strlen((char*)path);
#else
    if (rootinode!=0) {
        return ERROR_EPERM;
    }
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    if (pleng==0) {
        return ERROR_EINVAL;
    }
    for (uint32_t i=0 ; i<pleng ; i++) {
        if (path[i]==0) {
            return ERROR_EINVAL;
        }
    }
#endif

    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_TRASH) {
        return ERROR_ENOENT;
    }
    uint8_t *newpath = (uint8_t*)malloc(pleng);
    passert(newpath);
    free(p->parents->name);
    memcpy(newpath,path,pleng);
    p->parents->name = newpath;
    p->parents->nleng = pleng;

#ifndef METARESTORE
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SETPATH(%"PRIu32",%s)",(uint32_t)CServerCore::get_time(),inode,CFsNode::escape_name(pleng,newpath));
#else
    CFileSysMgr::s_MetaVersion++;
#endif

    return STATUS_OK;
}

#ifndef METARESTORE
uint8_t fs_undel(uint32_t rootinode,uint8_t sesflags,uint32_t inode) {
#else
uint8_t fs_undel(uint32_t ts,uint32_t inode) {
#endif

#ifndef METARESTORE
    if (rootinode!=0) {
        return ERROR_EPERM;
    }
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    uint32_t ts = CServerCore::get_time();
#endif
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_TRASH) {
        return ERROR_ENOENT;
    }
    uint8_t status = fsnodes_undel(ts,p);

#ifndef METARESTORE
    if (status==STATUS_OK) {
        changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|UNDEL(%"PRIu32")",ts,inode);
    }
#else
    CFileSysMgr::s_MetaVersion++;
#endif

    return status;
}

#ifndef METARESTORE
uint8_t fs_purge(uint32_t rootinode,uint8_t sesflags,uint32_t inode) {
#else
uint8_t fs_purge(uint32_t ts,uint32_t inode) {
#endif

#ifndef METARESTORE
    if (rootinode!=0) {
        return ERROR_EPERM;
    }
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    uint32_t ts = CServerCore::get_time();
#endif
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_TRASH) {
        return ERROR_ENOENT;
    }
    fsnodes_purge(ts,p);
#ifndef METARESTORE
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|PURGE(%"PRIu32")",ts,inode);
#else
    CFileSysMgr::s_MetaVersion++;
#endif

    return STATUS_OK;
}

#ifndef METARESTORE

uint8_t fs_getrootinode(uint32_t *rootinode,const uint8_t *path) {
    uint32_t nleng;
    CFsEdge *e;

    const uint8_t *name = path;
    CFsNode *p = CFsNode::s_root;
    for (;;) {
        while (*name=='/') {
            name++;
        }
        if (*name=='\0') {
            *rootinode = p->id;
            return STATUS_OK;
        }
        nleng=0;
        while (name[nleng] && name[nleng]!='/') {
            nleng++;
        }
        if (CFsNode::name_check(nleng,name)<0) {
            return ERROR_EINVAL;
        }
        e = p->lookup(nleng,name);
        if (!e) {
            return ERROR_ENOENT;
        }
        p = e->child;
        if (p->type!=TYPE_DIRECTORY) {
            return ERROR_ENOTDIR;
        }
        name += nleng;
    }
}

void fs_statfs(uint32_t rootinode,uint8_t sesflags,
               uint64_t *totalspace,uint64_t *availspace,uint64_t *trspace,uint64_t *respace,uint32_t *inodes)
{
    CFsNode *rn;
    (void)sesflags;

    if (rootinode==MFS_ROOT_ID) {
        *trspace = CFileSysMgr::s_trashspace;
        *respace = CFileSysMgr::s_reservedspace;
        rn = CFsNode::s_root;
    } else {
        *trspace = 0;
        *respace = 0;
        rn = CFsNode::id_to_node(rootinode);
    }

    if (!rn || rn->type!=TYPE_DIRECTORY) {
        *totalspace = 0;
        *availspace = 0;
        *inodes = 0;
    } else {
        CChunkSvrMgr::getInstance()->get_allspace(totalspace,availspace);
        STStatsRec sr;
        rn->get_stats(&sr);
        *inodes = sr.inodes;
        CFsQuota *qn = rn->data.ddata.quota;
        if (qn && (qn->flags&QUOTA_FLAG_HREALSIZE)) {
            if (sr.realsize>=qn->hrealsize) {
                *availspace = 0;
            } else if (*availspace > qn->hrealsize - sr.realsize) {
                *availspace = qn->hrealsize - sr.realsize;
            }
            if (*totalspace > qn->hrealsize) {
                *totalspace = qn->hrealsize;
            }
        }
        if (sr.realsize + *availspace < *totalspace) {
            *totalspace = sr.realsize + *availspace;
        }
    }
    stats_statfs++;
}

uint8_t fs_access(uint32_t rootinode,uint8_t sesflags,
                  uint32_t inode,uint32_t uid,uint32_t gid,int modemask)
{
    if ((sesflags&SESFLAG_READONLY) && (modemask&MODE_MASK_W)) {
        return ERROR_EROFS;
    }

    CFsNode *p,*rn;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    return fsnodes_access(p,uid,gid,modemask,sesflags)?STATUS_OK:ERROR_EACCES;
}

uint8_t fs_lookup(uint32_t rootinode,uint8_t sesflags,
                  uint32_t parent,
                  uint16_t nleng,const uint8_t *name,
                  uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                  uint32_t *inode,uint8_t attr[35])
{
    *inode = 0;
    memset(attr,0,35);

    CFsNode *wd,*rn;
    if (rootinode==MFS_ROOT_ID) {
        rn = CFsNode::s_root;
        wd = CFsNode::id_to_node(parent);
        if (!wd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (parent==MFS_ROOT_ID) {
            parent = rootinode;
            wd = rn;
        } else {
            wd = CFsNode::id_to_node(parent);
            if (!wd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,wd)) {
                return ERROR_EPERM;
            }
        }
    }

    if (wd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }

    if (!fsnodes_access(wd,uid,gid,MODE_MASK_X,sesflags)) {
        return ERROR_EACCES;
    }

    if (name[0]=='.') {
        if (nleng==1) {	// self
            if (parent==rootinode) {
                *inode = MFS_ROOT_ID;
            } else {
                *inode = wd->id;
            }
            fsnodes_fill_attr(wd,wd,uid,gid,auid,agid,sesflags,attr);
            stats_lookup++;
            return STATUS_OK;
        }
        if (nleng==2 && name[1]=='.') {	// parent
            if (parent==rootinode) {
                *inode = MFS_ROOT_ID;
                fsnodes_fill_attr(wd,wd,uid,gid,auid,agid,sesflags,attr);
            } else {
                if (wd->parents) {
                    if (wd->parents->parent->id==rootinode) {
                        *inode = MFS_ROOT_ID;
                    } else {
                        *inode = wd->parents->parent->id;
                    }
                    fsnodes_fill_attr(wd->parents->parent,wd,uid,gid,auid,agid,sesflags,attr);
                } else {
                    *inode=MFS_ROOT_ID; // rn->id;
                    fsnodes_fill_attr(rn,wd,uid,gid,auid,agid,sesflags,attr);
                }
            }
            stats_lookup++;
            return STATUS_OK;
        }
    }

    if (CFsNode::name_check(nleng,name)<0) {
        return ERROR_EINVAL;
    }

    CFsEdge *e = wd->lookup(nleng,name);
    if (!e) {
        return ERROR_ENOENT;
    }

    *inode = e->child->id;
    fsnodes_fill_attr(e->child,wd,uid,gid,auid,agid,sesflags,attr);
    stats_lookup++;
    return STATUS_OK;
}

uint8_t fs_getattr(uint32_t rootinode,uint8_t sesflags,
                   uint32_t inode,
                   uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                   uint8_t attr[35])
{
    (void)sesflags;
    memset(attr,0,35);

    CFsNode *p,*rn;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    fsnodes_fill_attr(p,NULL,uid,gid,auid,agid,sesflags,attr);
    stats_getattr++;
    return STATUS_OK;
}

uint8_t fs_try_setlength(uint32_t rootinode,uint8_t sesflags,
                         uint32_t inode,uint8_t opened,
                         uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,uint64_t length,uint8_t attr[35],uint64_t *chunkid) 
{
    memset(attr,0,35);
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    CFsNode *p,*rn;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
    if (opened==0) {
        if (!fsnodes_access(p,uid,gid,MODE_MASK_W,sesflags)) {
            return ERROR_EACCES;
        }
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    if (length>p->data.fdata.length) {
        if (p->test_quota()) {
            return ERROR_QUOTA;
        }
    }

    if (length&MFSCHUNKMASK) {
        uint32_t indx = (length>>MFSCHUNKBITS);
        if (indx<p->data.fdata.chunks) {
            uint64_t ochunkid = p->data.fdata.chunktab[indx];
            if (ochunkid>0) {
                uint8_t status;
                uint64_t nchunkid;
                status = chunk_multi_truncate(&nchunkid,ochunkid,length&MFSCHUNKMASK,p->goal);
                if (status!=STATUS_OK) {
                    return status;
                }
                p->data.fdata.chunktab[indx] = nchunkid;
                *chunkid = nchunkid;
                changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|TRUNC(%"PRIu32",%"PRIu32"):%"PRIu64,(uint32_t)CServerCore::get_time(),inode,indx,nchunkid);
                return ERROR_DELAYED;
            }
        }
    }
    fsnodes_fill_attr(p,NULL,uid,gid,auid,agid,sesflags,attr);
    stats_setattr++;
    return STATUS_OK;
}
#endif

#ifdef METARESTORE
uint8_t fs_trunc(uint32_t ts,uint32_t inode,uint32_t indx,uint64_t chunkid) {
    uint64_t ochunkid,nchunkid;
    uint8_t status;
    CFsNode *p;
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EINVAL;
    }
    if (indx>MAX_INDEX) {
        return ERROR_INDEXTOOBIG;
    }
    if (indx>=p->data.fdata.chunks) {
        return ERROR_EINVAL;
    }
    ochunkid = p->data.fdata.chunktab[indx];
    status = chunk_multi_truncate(ts,&nchunkid,ochunkid,p->goal);
    if (status!=STATUS_OK) {
        return status;
    }
    if (chunkid!=nchunkid) {
        return ERROR_MISMATCH;
    }
    p->data.fdata.chunktab[indx] = nchunkid;
    CFileSysMgr::s_MetaVersion++;
    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint8_t fs_end_setlength(uint64_t chunkid) {
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|UNLOCK(%"PRIu64")",(uint32_t)CServerCore::get_time(),chunkid);
    return ChkMgr->chunk_unlock(chunkid);
}
#else
uint8_t fs_unlock(uint64_t chunkid) {
    CFileSysMgr::s_MetaVersion++;
    return ChkMgr->chunk_unlock(chunkid);
}
#endif

#ifndef METARESTORE
uint8_t fs_do_setlength(uint32_t rootinode,uint8_t sesflags,
                        uint32_t inode,
                        uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                        uint64_t length,uint8_t attr[35])
{
    CFsNode *p,*rn;
    memset(attr,0,35);
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    p->set_length(length);
    uint32_t ts = CServerCore::get_time();
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|LENGTH(%"PRIu32",%"PRIu64")",ts,inode,p->data.fdata.length);
    p->ctime = p->mtime = ts;
    fsnodes_fill_attr(p,NULL,uid,gid,auid,agid,sesflags,attr);

    stats_setattr++;
    return STATUS_OK;
}


uint8_t fs_setattr(uint32_t rootinode,uint8_t sesflags,
                   uint32_t inode,
                   uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                   uint8_t setmask,uint16_t attrmode,
                   uint32_t attruid,uint32_t attrgid,
                   uint32_t attratime,uint32_t attrmtime,
                   uint8_t sugidclearmode,uint8_t attr[35])
{
    memset(attr,0,35);
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    CFsNode *p,*rn;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    if (uid!=0 && (sesflags&SESFLAG_MAPALL) && (setmask&(SET_UID_FLAG|SET_GID_FLAG))) {
        return ERROR_EPERM;
    }
    if ((p->mode&(EATTR_NOOWNER<<12))==0) {
        if (uid!=0 && uid!=p->uid && (setmask&(SET_MODE_FLAG|SET_UID_FLAG|SET_GID_FLAG|SET_ATIME_FLAG|SET_MTIME_FLAG))) {
            return ERROR_EPERM;
        }
    }
    if (uid!=0 && uid!=attruid && (setmask&SET_UID_FLAG)) {
        return ERROR_EPERM;
    }
    if ((sesflags&SESFLAG_IGNOREGID)==0) {
        if (uid!=0 && gid!=attrgid && (setmask&SET_GID_FLAG)) {
            return ERROR_EPERM;
        }
    }
    // first ignore sugid clears done by kernel
    if ((setmask&(SET_UID_FLAG|SET_GID_FLAG)) && (setmask&SET_MODE_FLAG)) {	// chown+chmod = chown with sugid clears
        attrmode |= (p->mode & 06000);
    }
    // then do it yourself
    if ((p->mode & 06000) && (setmask&(SET_UID_FLAG|SET_GID_FLAG))) { // this is "chown" operation and suid or sgid bit is set
        switch (sugidclearmode) {
        case SUGID_CLEAR_MODE_ALWAYS:
            p->mode &= 0171777; // safest approach - always delete both suid and sgid
            attrmode &= 01777;
            break;
        case SUGID_CLEAR_MODE_OSX:
            if (uid!=0) { // OSX+Solaris - every change done by unprivileged user should clear suid and sgid
                p->mode &= 0171777;
                attrmode &= 01777;
            }
            break;
        case SUGID_CLEAR_MODE_BSD:
            if (uid!=0 && (setmask&SET_GID_FLAG) && p->gid!=attrgid) { // *BSD - like in OSX but only when something is actually changed
                p->mode &= 0171777;
                attrmode &= 01777;
            }
            break;
        case SUGID_CLEAR_MODE_EXT:
            if (p->type!=TYPE_DIRECTORY) {
                if (p->mode & 010) { // when group exec is set - clear both bits
                    p->mode &= 0171777;
                    attrmode &= 01777;
                } else { // when group exec is not set - clear suid only
                    p->mode &= 0173777;
                    attrmode &= 03777;
                }
            }
            break;
        case SUGID_CLEAR_MODE_XFS:
            if (p->type!=TYPE_DIRECTORY) { // similar to EXT3, but unprivileged users also clear suid/sgid bits on directories
                if (p->mode & 010) {
                    p->mode &= 0171777;
                    attrmode &= 01777;
                } else {
                    p->mode &= 0173777;
                    attrmode &= 03777;
                }
            } else if (uid!=0) {
                p->mode &= 0171777;
                attrmode &= 01777;
            }
            break;
        }
    }

    if (setmask&SET_MODE_FLAG) {
        p->mode = (attrmode & 07777) | (p->mode & 0xF000);
    }
    if (setmask&SET_UID_FLAG) {
        p->uid = attruid;
    }
    if (setmask&SET_GID_FLAG) {
        p->gid = attrgid;
    }
    // 
    if (setmask&SET_ATIME_FLAG) {
        p->atime = attratime;
    }
    if (setmask&SET_MTIME_FLAG) {
        p->mtime = attrmtime;
    }

    uint32_t ts = CServerCore::get_time();
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|ATTR(%"PRIu32",%"PRIu16",%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32")",ts,inode,p->mode & 07777,p->uid,p->gid,p->atime,p->mtime);
    p->ctime = ts;
    fsnodes_fill_attr(p,NULL,uid,gid,auid,agid,sesflags,attr);

    stats_setattr++;
    return STATUS_OK;
}
#endif


#ifdef METARESTORE
uint8_t fs_attr(uint32_t ts,uint32_t inode,uint32_t mode,uint32_t uid,uint32_t gid,uint32_t atime,uint32_t mtime)
{
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }

    if (mode>07777) {
        return ERROR_EINVAL;
    }

    p->mode = mode | (p->mode & 0xF000);
    p->uid = uid;
    p->gid = gid;
    p->atime = atime;
    p->mtime = mtime;
    p->ctime = ts;
    CFileSysMgr::s_MetaVersion++;

    return STATUS_OK;
}

uint8_t fs_length(uint32_t ts,uint32_t inode,uint64_t length) {
    CFsNode *p;
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EINVAL;
    }
    p->set_length(length);
    p->mtime = ts;
    p->ctime = ts;
    CFileSysMgr::s_MetaVersion++;
    return STATUS_OK;
}

#endif

#ifndef METARESTORE
uint8_t fs_readlink(uint32_t rootinode,uint8_t sesflags,
                    uint32_t inode,
                    uint32_t *pleng,uint8_t **path)
{
    (void)sesflags;
    *pleng = 0;
    *path = NULL;

    CFsNode *p,*rn;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
    if (p->type!=TYPE_SYMLINK) {
        return ERROR_EINVAL;
    }
    *pleng = p->data.sdata.pleng;
    *path = p->data.sdata.path;

    uint32_t ts = CServerCore::get_time();
    if (p->atime!=ts) {
        p->atime = ts;
        changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|ACCESS(%"PRIu32")",ts,inode);
    }
    stats_readlink++;

    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint8_t fs_symlink(uint32_t rootinode,uint8_t sesflags,
                   uint32_t parent,
                   uint16_t nleng,const uint8_t *name,
                   uint32_t pleng,const uint8_t *path,
                   uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                   uint32_t *inode,uint8_t attr[35])
{
#else
uint8_t fs_symlink(uint32_t ts,uint32_t parent,uint32_t nleng,const uint8_t *name,const uint8_t *path,uint32_t uid,uint32_t gid,uint32_t inode) {
    uint32_t pleng;
#endif
    CFsNode *wd,*p;
    uint8_t *newpath;
#ifndef METARESTORE
    CFsNode *rn;
    STStatsRec sr;
    uint32_t i;
    *inode = 0;
    memset(attr,0,35);
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    if (pleng==0) {
        return ERROR_EINVAL;
    }
    for (i=0 ; i<pleng ; i++) {
        if (path[i]==0) {
            return ERROR_EINVAL;
        }
    }

    if (rootinode==MFS_ROOT_ID) {
        wd = CFsNode::id_to_node(parent);
        if (!wd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (parent==MFS_ROOT_ID) {
            parent = rootinode;
            wd = rn;
        } else {
            wd = CFsNode::id_to_node(parent);
            if (!wd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,wd)) {
                return ERROR_EPERM;
            }
        }
    }
#else
    pleng = strlen((const char*)path);
    wd = CFsNode::id_to_node(parent);
    if (!wd) {
        return ERROR_ENOENT;
    }
#endif
    if (wd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
#ifndef METARESTORE
    if (!fsnodes_access(wd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
#endif
    if (CFsNode::name_check(nleng,name)<0) {
        return ERROR_EINVAL;
    }

    if (wd->nameisused(nleng,name)) {
        return ERROR_EEXIST;
    }
    if (wd->test_quota()) {
        return ERROR_QUOTA;
    }
    newpath = (uint8_t*)malloc(pleng);
    passert(newpath);
#ifndef METARESTORE
    p = CFsNode::create_node(CServerCore::get_time(),wd,nleng,name,TYPE_SYMLINK,0777,uid,gid,0);
#else
    p = CFsNode::create_node(ts,wd,nleng,name,TYPE_SYMLINK,0777,uid,gid,0);
#endif
    memcpy(newpath,path,pleng);
    p->data.sdata.path = newpath;
    p->data.sdata.pleng = pleng;
#ifndef METARESTORE

    memset(&sr,0,sizeof(STStatsRec));
    sr.length = pleng;
    wd->add_stats(&sr);

    *inode = p->id;
    fsnodes_fill_attr(p,wd,uid,gid,auid,agid,sesflags,attr);
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SYMLINK(%"PRIu32",%s,%s,%"PRIu32",%"PRIu32"):%"PRIu32,(uint32_t)CServerCore::get_time(),parent,CFsNode::escape_name(nleng,name),CFsNode::escape_name(pleng,newpath),uid,gid,p->id);
    stats_symlink++;
#else
    if (inode!=p->id) {
        return ERROR_MISMATCH;
    }
    CFileSysMgr::s_MetaVersion++;
#endif
    return STATUS_OK;
}

#ifndef METARESTORE
uint8_t fs_mknod(uint32_t rootinode,uint8_t sesflags,
                 uint32_t parent,
                 uint16_t nleng,const uint8_t *name,
                 uint8_t type,uint16_t mode,
                 uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                 uint32_t rdev,uint32_t *inode,uint8_t attr[35])
{
    *inode = 0;
    memset(attr,0,35);
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    if (type!=TYPE_FILE && type!=TYPE_SOCKET && type!=TYPE_FIFO && type!=TYPE_BLOCKDEV && type!=TYPE_CHARDEV) {
        return ERROR_EINVAL;
    }

    CFsNode *wd,*rn;
    if (rootinode==MFS_ROOT_ID) {
        wd = CFsNode::id_to_node(parent);
        if (!wd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (parent==MFS_ROOT_ID) {
            parent = rootinode;
            wd = rn;
        } else {
            wd = CFsNode::id_to_node(parent);
            if (!wd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,wd)) {
                return ERROR_EPERM;
            }
        }
    }
    if (wd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
    if (!fsnodes_access(wd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
    if (CFsNode::name_check(nleng,name)<0) {
        return ERROR_EINVAL;
    }
    if (wd->nameisused(nleng,name)) {
        return ERROR_EEXIST;
    }
    if (wd->test_quota()) {
        return ERROR_QUOTA;
    }

    CFsNode *p = CFsNode::create_node(CServerCore::get_time(),wd,nleng,name,type,mode,uid,gid,0);
    if (type==TYPE_BLOCKDEV || type==TYPE_CHARDEV) {
        p->data.devdata.rdev = rdev;
    }
    *inode = p->id;
    fsnodes_fill_attr(p,wd,uid,gid,auid,agid,sesflags,attr);
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|CREATE(%"PRIu32",%s,%c,%"PRIu16",%"PRIu32",%"PRIu32",%"PRIu32"):%"PRIu32,
        (uint32_t)CServerCore::get_time(),parent,CFsNode::escape_name(nleng,name),type,mode,uid,gid,rdev,p->id);
    stats_mknod++;

    return STATUS_OK;
}

uint8_t fs_mkdir(uint32_t rootinode,uint8_t sesflags,
                 uint32_t parent,
                 uint16_t nleng,const uint8_t *name,
                 uint16_t mode,
                 uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                 uint8_t copysgid,uint32_t *inode,uint8_t attr[35])
{
    *inode = 0;
    memset(attr,0,35);
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    CFsNode *wd,*rn;
    if (rootinode==MFS_ROOT_ID) {
        wd = CFsNode::id_to_node(parent);
        if (!wd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (parent==MFS_ROOT_ID) {
            parent = rootinode;
            wd = rn;
        } else {
            wd = CFsNode::id_to_node(parent);
            if (!wd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,wd)) {
                return ERROR_EPERM;
            }
        }
    }

    if (wd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
    if (!fsnodes_access(wd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
    if (CFsNode::name_check(nleng,name)<0) {
        return ERROR_EINVAL;
    }
    if (wd->nameisused(nleng,name)) {
        return ERROR_EEXIST;
    }
    if (wd->test_quota()) {
        return ERROR_QUOTA;
    }

    CFsNode *p = CFsNode::create_node(CServerCore::get_time(),wd,nleng,name,TYPE_DIRECTORY,mode,uid,gid,copysgid);
    *inode = p->id;
    fsnodes_fill_attr(p,wd,uid,gid,auid,agid,sesflags,attr);
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|CREATE(%"PRIu32",%s,%c,%"PRIu16",%"PRIu32",%"PRIu32",%"PRIu32"):%"PRIu32,(uint32_t)CServerCore::get_time(),parent,CFsNode::escape_name(nleng,name),TYPE_DIRECTORY,mode,uid,gid,0,p->id);
    stats_mkdir++;

    return STATUS_OK;
}
#else
uint8_t fs_create(uint32_t ts,uint32_t parent,uint32_t nleng,const uint8_t *name,uint8_t type,uint32_t mode,uint32_t uid,uint32_t gid,uint32_t rdev,uint32_t inode) {
    CFsNode *wd,*p;
    if (type!=TYPE_FILE && type!=TYPE_SOCKET && type!=TYPE_FIFO && type!=TYPE_BLOCKDEV && type!=TYPE_CHARDEV && type!=TYPE_DIRECTORY) {
        return ERROR_EINVAL;
    }
    wd = CFsNode::id_to_node(parent);
    if (!wd) {
        return ERROR_ENOENT;
    }
    if (wd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
    if (wd->nameisused(nleng,name)) {
        return ERROR_EEXIST;
    }
    if (wd->test_quota()) {
        return ERROR_QUOTA;
    }
    p = CFsNode::create_node(ts,wd,nleng,name,type,mode,uid,gid,0);
    if (type==TYPE_BLOCKDEV || type==TYPE_CHARDEV) {
        p->data.devdata.rdev = rdev;
    }
    if (inode!=p->id) {
        return ERROR_MISMATCH;
    }
    CFileSysMgr::s_MetaVersion++;
    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint8_t fs_unlink(uint32_t rootinode,uint8_t sesflags,
                  uint32_t parent,
                  uint16_t nleng,const uint8_t *name,
                  uint32_t uid,uint32_t gid)
{
    CFsNode *wd,*rn;
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    if (rootinode==MFS_ROOT_ID) {
        wd = CFsNode::id_to_node(parent);
        if (!wd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (parent==MFS_ROOT_ID) {
            parent = rootinode;
            wd = rn;
        } else {
            wd = CFsNode::id_to_node(parent);
            if (!wd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,wd)) {
                return ERROR_EPERM;
            }
        }
    }

    if (wd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
    if (!fsnodes_access(wd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
    if (CFsNode::name_check(nleng,name)<0) {
        return ERROR_EINVAL;
    }

    CFsEdge *e = wd->lookup(nleng,name);
    if (!e) {
        return ERROR_ENOENT;
    }
    if (!fsnodes_sticky_access(wd,e->child,uid)) {
        return ERROR_EPERM;
    }
    if (e->child->type==TYPE_DIRECTORY) {
        return ERROR_EPERM;
    }

    uint32_t ts = CServerCore::get_time();
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|UNLINK(%"PRIu32",%s):%"PRIu32,ts,parent,CFsNode::escape_name(nleng,name),e->child->id);
    CFsNode::unlink_edge(ts,e);
    stats_unlink++;

    return STATUS_OK;

}

uint8_t fs_rmdir(uint32_t rootinode,uint8_t sesflags,
                 uint32_t parent,
                 uint16_t nleng,const uint8_t *name,
                 uint32_t uid,uint32_t gid)
{
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    CFsNode *wd,*rn;
    if (rootinode==MFS_ROOT_ID) {
        wd = CFsNode::id_to_node(parent);
        if (!wd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (parent==MFS_ROOT_ID) {
            parent = rootinode;
            wd = rn;
        } else {
            wd = CFsNode::id_to_node(parent);
            if (!wd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,wd)) {
                return ERROR_EPERM;
            }
        }
    }

    if (wd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
    if (!fsnodes_access(wd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
    if (CFsNode::name_check(nleng,name)<0) {
        return ERROR_EINVAL;
    }

    CFsEdge *e = wd->lookup(nleng,name);
    if (!e) {
        return ERROR_ENOENT;
    }
    if (!fsnodes_sticky_access(wd,e->child,uid)) {
        return ERROR_EPERM;
    }
    if (e->child->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
    if (e->child->data.ddata.children!=NULL) {
        return ERROR_ENOTEMPTY;
    }

    uint32_t ts = CServerCore::get_time();
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|UNLINK(%"PRIu32",%s):%"PRIu32,ts,parent,CFsNode::escape_name(nleng,name),e->child->id);
    CFsNode::unlink_edge(ts,e);
    stats_rmdir++;
    return STATUS_OK;
}
#else
uint8_t fs_unlink(uint32_t ts,uint32_t parent,uint32_t nleng,const uint8_t *name,uint32_t inode)
{
    CFsNode *wd = CFsNode::id_to_node(parent);
    if (!wd) {
        return ERROR_ENOENT;
    }
    if (wd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }

    CFsEdge *e = wd->lookup(nleng,name);
    if (!e) {
        return ERROR_ENOENT;
    }
    if (e->child->id!=inode) {
        return ERROR_MISMATCH;
    }
    if (e->child->type==TYPE_DIRECTORY && e->child->data.ddata.children!=NULL) {
        return ERROR_ENOTEMPTY;
    }
    CFsNode::unlink_edge(ts,e);
    CFileSysMgr::s_MetaVersion++;
    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint8_t fs_rename(uint32_t rootinode,uint8_t sesflags,
                  uint32_t parent_src,
                  uint16_t nleng_src,const uint8_t *name_src,
                  uint32_t parent_dst,
                  uint16_t nleng_dst,const uint8_t *name_dst,
                  uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                  uint32_t *inode,uint8_t attr[35])
{
    uint32_t ts;
#else
uint8_t fs_move(uint32_t ts,uint32_t parent_src,
                uint32_t nleng_src,const uint8_t *name_src,
                uint32_t parent_dst,
                uint32_t nleng_dst,const uint8_t *name_dst,
                uint32_t inode)
{
#endif
    CFsNode *swd;
    CFsEdge *se;
    CFsNode *dwd;
    CFsEdge *de;
    CFsNode *node;
#ifndef METARESTORE
    CFsNode *rn;
    ts = CServerCore::get_time();
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    if (rootinode==MFS_ROOT_ID) {
        swd = CFsNode::id_to_node(parent_src);
        if (!swd) {
            return ERROR_ENOENT;
        }
        dwd = CFsNode::id_to_node(parent_dst);
        if (!dwd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (parent_src==MFS_ROOT_ID) {
            parent_src = rootinode;
            swd = rn;
        } else {
            swd = CFsNode::id_to_node(parent_src);
            if (!swd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,swd)) {
                return ERROR_EPERM;
            }
        }
        if (parent_dst==MFS_ROOT_ID) {
            parent_dst = rootinode;
            dwd = rn;
        } else {
            dwd = CFsNode::id_to_node(parent_dst);
            if (!dwd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,dwd)) {
                return ERROR_EPERM;
            }
        }
    }
#else
    swd = CFsNode::id_to_node(parent_src);
    if (!swd) {
        return ERROR_ENOENT;
    }
    dwd = CFsNode::id_to_node(parent_dst);
    if (!dwd) {
        return ERROR_ENOENT;
    }
#endif
    if (swd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
#ifndef METARESTORE
    if (!fsnodes_access(swd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
#endif
    if (CFsNode::name_check(nleng_src,name_src)<0) {
        return ERROR_EINVAL;
    }
    se = swd->lookup(nleng_src,name_src);
    if (!se) {
        return ERROR_ENOENT;
    }
    node = se->child;
#ifndef METARESTORE
    if (!fsnodes_sticky_access(swd,node,uid)) {
        return ERROR_EPERM;
    }
#endif
#ifdef METARESTORE
    if (node->id!=inode) {
        return ERROR_MISMATCH;
    }
#endif
    if (dwd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
#ifndef METARESTORE
    if (!fsnodes_access(dwd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
#endif
    if (se->child->type==TYPE_DIRECTORY) {
        if (fsnodes_isancestor(se->child,dwd)) {
            return ERROR_EINVAL;
        }
    }
    if (CFsNode::name_check(nleng_dst,name_dst)<0) {
        return ERROR_EINVAL;
        //		name_dst = fp->name;
    }
    if (dwd->test_quota()) {
        return ERROR_QUOTA;
    }
    de = dwd->lookup(nleng_dst,name_dst);
    if (de) {
        if (de->child->type==TYPE_DIRECTORY && de->child->data.ddata.children!=NULL) {
            return ERROR_ENOTEMPTY;
        }
#ifndef METARESTORE
        if (!fsnodes_sticky_access(dwd,de->child,uid)) {
            return ERROR_EPERM;
        }
#endif
        CFsNode::unlink_edge(ts,de);
    }
    se->remove_edge(ts);
    CFsNode::link_edge(ts,dwd,node,nleng_dst,name_dst);
#ifndef METARESTORE
    *inode = node->id;
    fsnodes_fill_attr(node,dwd,uid,gid,auid,agid,sesflags,attr);
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|MOVE(%"PRIu32",%s,%"PRIu32",%s):%"PRIu32,(uint32_t)CServerCore::get_time(),parent_src,CFsNode::escape_name(nleng_src,name_src),parent_dst,CFsNode::escape_name(nleng_dst,name_dst),node->id);
    stats_rename++;
#else
    CFileSysMgr::s_MetaVersion++;
#endif
    return STATUS_OK;
}

#ifndef METARESTORE
uint8_t fs_link(uint32_t rootinode,uint8_t sesflags,
                uint32_t inode_src,uint32_t parent_dst,
                uint16_t nleng_dst,const uint8_t *name_dst,
                uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                uint32_t *inode,uint8_t attr[35])
{
    uint32_t ts;
#else
uint8_t fs_link(uint32_t ts,uint32_t inode_src,uint32_t parent_dst,uint32_t nleng_dst,uint8_t *name_dst)
{
#endif
    CFsNode *sp;
    CFsNode *dwd;
#ifndef METARESTORE
    CFsNode *rn;
    ts = CServerCore::get_time();
    *inode = 0;
    memset(attr,0,35);
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    if (rootinode==MFS_ROOT_ID) {
        sp = CFsNode::id_to_node(inode_src);
        if (!sp) {
            return ERROR_ENOENT;
        }
        dwd = CFsNode::id_to_node(parent_dst);
        if (!dwd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode_src==MFS_ROOT_ID) {
            inode_src = rootinode;
            sp = rn;
        } else {
            sp = CFsNode::id_to_node(inode_src);
            if (!sp) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,sp)) {
                return ERROR_EPERM;
            }
        }
        if (parent_dst==MFS_ROOT_ID) {
            parent_dst = rootinode;
            dwd = rn;
        } else {
            dwd = CFsNode::id_to_node(parent_dst);
            if (!dwd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,dwd)) {
                return ERROR_EPERM;
            }
        }
    }
#else
    sp = CFsNode::id_to_node(inode_src);
    if (!sp) {
        return ERROR_ENOENT;
    }
    dwd = CFsNode::id_to_node(parent_dst);
    if (!dwd) {
        return ERROR_ENOENT;
    }
#endif
    if (sp->type==TYPE_TRASH || sp->type==TYPE_RESERVED) {
        return ERROR_ENOENT;
    }
    if (sp->type==TYPE_DIRECTORY) {
        return ERROR_EPERM;
    }
    if (dwd->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
#ifndef METARESTORE
    if (!fsnodes_access(dwd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
#endif
    if (CFsNode::name_check(nleng_dst,name_dst)<0) {
        return ERROR_EINVAL;
    }
    if (dwd->nameisused(nleng_dst,name_dst)) {
        return ERROR_EEXIST;
    }
    if (dwd->test_quota()) {
        return ERROR_QUOTA;
    }
    CFsNode::link_edge(ts,dwd,sp,nleng_dst,name_dst);
#ifndef METARESTORE
    *inode = inode_src;
    fsnodes_fill_attr(sp,dwd,uid,gid,auid,agid,sesflags,attr);
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|LINK(%"PRIu32",%"PRIu32",%s)",(uint32_t)CServerCore::get_time(),inode_src,parent_dst,CFsNode::escape_name(nleng_dst,name_dst));
    stats_link++;
#else
    CFileSysMgr::s_MetaVersion++;
#endif
    return STATUS_OK;
}

#ifndef METARESTORE
uint8_t fs_snapshot(uint32_t rootinode,uint8_t sesflags,
                    uint32_t inode_src,uint32_t parent_dst,
                    uint16_t nleng_dst,const uint8_t *name_dst,
                    uint32_t uid,uint32_t gid,uint8_t canoverwrite) {
    uint32_t ts;
    CFsNode *rn;
#else
uint8_t fs_snapshot(uint32_t ts,uint32_t inode_src,uint32_t parent_dst,
                    uint16_t nleng_dst,uint8_t *name_dst,
                    uint8_t canoverwrite) 
{
#endif
    CFsNode *sp;
    CFsNode *dwd;
    uint8_t status;
#ifndef METARESTORE
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    if (rootinode==MFS_ROOT_ID) {
        sp = CFsNode::id_to_node(inode_src);
        if (!sp) {
            return ERROR_ENOENT;
        }
        dwd = CFsNode::id_to_node(parent_dst);
        if (!dwd) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode_src==MFS_ROOT_ID) {
            inode_src = rootinode;
            sp = rn;
        } else {
            sp = CFsNode::id_to_node(inode_src);
            if (!sp) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,sp)) {
                return ERROR_EPERM;
            }
        }
        if (parent_dst==MFS_ROOT_ID) {
            parent_dst = rootinode;
            dwd = rn;
        } else {
            dwd = CFsNode::id_to_node(parent_dst);
            if (!dwd) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,dwd)) {
                return ERROR_EPERM;
            }
        }
    }
#else
    sp = CFsNode::id_to_node(inode_src);
    if (!sp) {
        return ERROR_ENOENT;
    }
    dwd = CFsNode::id_to_node(parent_dst);
    if (!dwd) {
        return ERROR_ENOENT;
    }
#endif

#ifndef METARESTORE
    if (!fsnodes_access(sp,uid,gid,MODE_MASK_R,sesflags)) {
        return ERROR_EACCES;
    }
#endif
    if (dwd->type!=TYPE_DIRECTORY) {
        return ERROR_EPERM;
    }
    if (sp->type==TYPE_DIRECTORY) {
        if (sp==dwd || fsnodes_isancestor(sp,dwd)) {
            return ERROR_EINVAL;
        }
    }
#ifndef METARESTORE
    if (!fsnodes_access(dwd,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
#endif
    if (dwd->test_quota()) {
        return ERROR_QUOTA;
    }
    status = fsnodes_snapshot_test(sp,sp,dwd,nleng_dst,name_dst,canoverwrite);
    if (status!=STATUS_OK) {
        return status;
    }

#ifndef METARESTORE
    ts = CServerCore::get_time();
#endif
    fsnodes_snapshot(ts,sp,dwd,nleng_dst,name_dst);
#ifndef METARESTORE
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SNAPSHOT(%"PRIu32",%"PRIu32",%s,%"PRIu8")",ts,inode_src,parent_dst,CFsNode::escape_name(nleng_dst,name_dst),canoverwrite);
#else
    CFileSysMgr::s_MetaVersion++;
#endif

    return STATUS_OK;
}

#ifndef METARESTORE
uint8_t fs_append(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint32_t inode_src,uint32_t uid,uint32_t gid) {
    uint32_t ts;
    CFsNode *rn;
#else
uint8_t fs_append(uint32_t ts,uint32_t inode,uint32_t inode_src) {
#endif
    uint8_t status;
    CFsNode *p,*sp;
    if (inode==inode_src) {
        return ERROR_EINVAL;
    }
#ifndef METARESTORE
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    if (rootinode==MFS_ROOT_ID) {
        sp = CFsNode::id_to_node(inode_src);
        if (!sp) {
            return ERROR_ENOENT;
        }
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode_src==MFS_ROOT_ID) {
            inode_src = rootinode;
            sp = rn;
        } else {
            sp = CFsNode::id_to_node(inode_src);
            if (!sp) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,sp)) {
                return ERROR_EPERM;
            }
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
#else
    sp = CFsNode::id_to_node(inode_src);
    if (!sp) {
        return ERROR_ENOENT;
    }
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
#endif
    if (sp->type!=TYPE_FILE && sp->type!=TYPE_TRASH && sp->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
#ifndef METARESTORE
    if (!fsnodes_access(sp,uid,gid,MODE_MASK_R,sesflags)) {
        return ERROR_EACCES;
    }
#endif
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
#ifndef METARESTORE
    if (!fsnodes_access(p,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }
#endif
    if (p->test_quota()) {
        return ERROR_QUOTA;
    }
#ifndef METARESTORE
    ts = CServerCore::get_time();
#endif
    status = fsnodes_appendchunks(ts,p,sp);
    if (status!=STATUS_OK) {
        return status;
    }
#ifndef METARESTORE
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|APPEND(%"PRIu32",%"PRIu32")",ts,inode,inode_src);
#else
    CFileSysMgr::s_MetaVersion++;
#endif
    return STATUS_OK;
}

#ifndef METARESTORE
uint8_t fs_readdir_size(uint32_t rootinode,uint8_t sesflags,uint32_t inode,
                        uint32_t uid,uint32_t gid,
                        uint8_t flags,void **dnode,uint32_t *dbuffsize) 
{
    CFsNode *p,*rn;
    *dnode = NULL;
    *dbuffsize = 0;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    if (p->type!=TYPE_DIRECTORY) {
        return ERROR_ENOTDIR;
    }
    if (!fsnodes_access(p,uid,gid,MODE_MASK_R,sesflags)) {
        return ERROR_EACCES;
    }
    *dnode = p;
    *dbuffsize = p->getdir_size(flags&GETDIR_FLAG_WITHATTR);

    return STATUS_OK;
}

void fs_readdir_data(uint32_t rootinode,uint8_t sesflags,
                     uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                     uint8_t flags,void *dnode,uint8_t *dbuff) 
{
    CFsNode *p = (CFsNode*)dnode;
    uint32_t ts = CServerCore::get_time();

    if (p->atime!=ts) {
        p->atime = ts;
        changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|ACCESS(%"PRIu32")",ts,p->id);
        fsnodes_getdirdata(rootinode,uid,gid,auid,agid,sesflags,p,dbuff,flags&GETDIR_FLAG_WITHATTR);
    } else {
        fsnodes_getdirdata(rootinode,uid,gid,auid,agid,sesflags,p,dbuff,flags&GETDIR_FLAG_WITHATTR);
    }
    stats_readdir++;
}

uint8_t fs_checkfile(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint32_t chunkcount[11])
{
    CFsNode *p,*rn;
    (void)sesflags;
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    p->checkfile(chunkcount);
    return STATUS_OK;
}

uint8_t fs_opencheck(uint32_t rootinode,uint8_t sesflags,uint32_t inode,
                     uint32_t uid,uint32_t gid,uint32_t auid,uint32_t agid,
                     uint8_t flags,uint8_t attr[35]) 
{
    CFsNode *p,*rn;
    if ((sesflags&SESFLAG_READONLY) && (flags&WANT_WRITE)) {
        return ERROR_EROFS;
    }
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    if ((flags&AFTER_CREATE)==0) {
        uint8_t modemask=0;
        if (flags&WANT_READ) {
            modemask|=MODE_MASK_R;
        }
        if (flags&WANT_WRITE) {
            modemask|=MODE_MASK_W;
        }
        if (!fsnodes_access(p,uid,gid,modemask,sesflags)) {
            return ERROR_EACCES;
        }
    }
    fsnodes_fill_attr(p,NULL,uid,gid,auid,agid,sesflags,attr);
    stats_open++;
    return STATUS_OK;
}
#endif


uint8_t fs_acquire(uint32_t inode,uint32_t sessionid) 
{
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }

    STSIDRec *cr;
    for (cr=p->data.fdata.sessIDs ; cr ; cr=cr->next) {
        if (cr->sessionid==sessionid) {
            return ERROR_EINVAL;
        }
    }

    cr = sessionidrec_malloc();
    cr->sessionid = sessionid;
    cr->next = p->data.fdata.sessIDs;
    p->data.fdata.sessIDs = cr;
#ifndef METARESTORE
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|ACQUIRE(%"PRIu32",%"PRIu32")",(uint32_t)CServerCore::get_time(),inode,sessionid);
#else
    CFileSysMgr::s_MetaVersion++;
#endif

    return STATUS_OK;
}

uint8_t fs_release(uint32_t inode,uint32_t sessionid)
{
    STSIDRec *cr,**crp;
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    crp = &(p->data.fdata.sessIDs);
    while ((cr=*crp)) {
        if (cr->sessionid==sessionid) {
            *crp = cr->next;
            sessionidrec_free(cr);
#ifndef METARESTORE
            changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|RELEASE(%"PRIu32",%"PRIu32")",(uint32_t)CServerCore::get_time(),inode,sessionid);
#else
            CFileSysMgr::s_MetaVersion++;
#endif
            return STATUS_OK;
        } else {
            crp = &(cr->next);
        }
    }
#ifndef METARESTORE
    syslog(LOG_WARNING,"release: session not found");
#endif
    return ERROR_EINVAL;
}

#ifndef METARESTORE
uint8_t fs_readchunk(uint32_t inode,uint32_t indx,uint64_t *chunkid,uint64_t *length) 
{
    uint32_t ts = CServerCore::get_time();

    *chunkid = 0;
    *length = 0;
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    if (indx>MAX_INDEX) {
        return ERROR_INDEXTOOBIG;
    }

    if (indx<p->data.fdata.chunks) {
        *chunkid = p->data.fdata.chunktab[indx];
    }
    *length = p->data.fdata.length;
    if (p->atime!=ts) {
        p->atime = ts;
        changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|ACCESS(%"PRIu32")",ts,inode);
    }

    stats_read++;

    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint8_t fs_writechunk(uint32_t inode,uint32_t indx,uint64_t *chunkid,uint64_t *length,uint8_t *opflag)
{
    uint32_t i;
    uint64_t ochunkid,nchunkid;
    STStatsRec psr,nsr;
    CFsEdge *e;
    uint32_t ts = CServerCore::get_time();

    *chunkid = 0;
    *length = 0;
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    if (p->test_quota()) {
        return ERROR_QUOTA;
    }
    if (indx>MAX_INDEX) {
        return ERROR_INDEXTOOBIG;
    }
    p->get_stats(&psr);
    /* resize chunks structure */
    if (indx>=p->data.fdata.chunks) {
        uint32_t newsize;
        if (indx<8) {
            newsize=indx+1;
        } else if (indx<64) {
            newsize=(indx&0xFFFFFFF8)+8;
        } else {
            newsize = (indx&0xFFFFFFC0)+64;
        }
        if (p->data.fdata.chunktab==NULL) {
            p->data.fdata.chunktab = (uint64_t*)malloc(sizeof(uint64_t)*newsize);
        } else {
            p->data.fdata.chunktab = (uint64_t*)realloc(p->data.fdata.chunktab,sizeof(uint64_t)*newsize);
        }
        passert(p->data.fdata.chunktab);
        for (i=p->data.fdata.chunks ; i<newsize ; i++) {
            p->data.fdata.chunktab[i]=0;
        }
        p->data.fdata.chunks = newsize;
    }
    ochunkid = p->data.fdata.chunktab[indx];
    int status = chunk_multi_modify(&nchunkid,ochunkid,p->goal,opflag);

    if (status!=STATUS_OK) {
        return status;
    }
    p->data.fdata.chunktab[indx] = nchunkid;
    p->get_stats(&nsr);
    for (e=p->parents ; e ; e=e->nextParent) {
        if(e->parent)
            e->parent->add_sub_stats(&nsr,&psr);
    }
    *chunkid = nchunkid;
    *length = p->data.fdata.length;
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|WRITE(%"PRIu32",%"PRIu32",%"PRIu8"):%"PRIu64,ts,inode,indx,*opflag,nchunkid);
    if (p->mtime!=ts || p->ctime!=ts) {
        p->mtime = p->ctime = ts;
    }
    stats_write++;

    return STATUS_OK;
}
#else
uint8_t fs_write(uint32_t ts,uint32_t inode,uint32_t indx,uint8_t opflag,uint64_t chunkid) {
    int status;
    uint32_t i;
    uint64_t ochunkid,nchunkid;
    CFsNode *p;
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    if (p->test_quota()) {
        return ERROR_QUOTA;
    }
    if (indx>MAX_INDEX) {
        return ERROR_INDEXTOOBIG;
    }
    /* resize chunks structure */
    if (indx>=p->data.fdata.chunks) {
        uint32_t newsize;
        if (indx<8) {
            newsize=indx+1;
        } else if (indx<64) {
            newsize=(indx&0xFFFFFFF8)+8;
        } else {
            newsize = (indx&0xFFFFFFC0)+64;
        }
        if (p->data.fdata.chunktab==NULL) {
            p->data.fdata.chunktab = (uint64_t*)malloc(sizeof(uint64_t)*newsize);
        } else {
            p->data.fdata.chunktab = (uint64_t*)realloc(p->data.fdata.chunktab,sizeof(uint64_t)*newsize);
        }
        passert(p->data.fdata.chunktab);
        for (i=p->data.fdata.chunks ; i<newsize ; i++) {
            p->data.fdata.chunktab[i]=0;
        }
        p->data.fdata.chunks = newsize;
    }
    ochunkid = p->data.fdata.chunktab[indx];
    status = chunk_multi_modify(ts,&nchunkid,ochunkid,p->goal,opflag);
    if (status!=STATUS_OK) {
        return status;
    }
    if (nchunkid!=chunkid) {
        return ERROR_MISMATCH;
    }
    p->data.fdata.chunktab[indx] = nchunkid;
    CFileSysMgr::s_MetaVersion++;
    p->mtime = p->ctime = ts;
    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint8_t fs_writeend(uint32_t inode,uint64_t length,uint64_t chunkid) {
    uint32_t ts = CServerCore::get_time();
    if (length>0) {
        CFsNode *p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
        if (length>p->data.fdata.length) {
            p->set_length(length);
            p->mtime = p->ctime = ts;
            changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|LENGTH(%"PRIu32",%"PRIu64")",ts,inode,length);
        }
    }
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|UNLOCK(%"PRIu64")",ts,chunkid);
    return ChkMgr->chunk_unlock(chunkid);
}
#endif

#ifndef METARESTORE
void fs_incversion(uint64_t chunkid) {
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|INCVERSION(%"PRIu64")",(uint32_t)CServerCore::get_time(),chunkid);
}
#else
uint8_t fs_incversion(uint64_t chunkid) {
    CFileSysMgr::s_MetaVersion++;
    return CChunkMgr::getInstance()->chunk_increase_version(chunkid);
}
#endif


#ifndef METARESTORE
uint8_t fs_repair(uint32_t rootinode,uint8_t sesflags,uint32_t inode,
                  uint32_t uid,uint32_t gid,
                  uint32_t *notchanged,uint32_t *erased,uint32_t *repaired) 
{
    uint32_t nversion,indx;
    STStatsRec psr,nsr;
    CFsEdge *e;
    CFsNode *p,*rn;
    uint32_t ts = CServerCore::get_time();

    *notchanged = 0;
    *erased = 0;
    *repaired = 0;
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }

        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }

    if (!fsnodes_access(p,uid,gid,MODE_MASK_W,sesflags)) {
        return ERROR_EACCES;
    }

    p->get_stats(&psr);
    for (indx=0 ; indx<p->data.fdata.chunks ; indx++) {
        if (chunk_repair(p->goal,p->data.fdata.chunktab[indx],&nversion)) {
            changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|REPAIR(%"PRIu32",%"PRIu32"):%"PRIu32,ts,inode,indx,nversion);
            if (nversion>0) {
                (*repaired)++;
            } else {
                p->data.fdata.chunktab[indx] = 0;
                (*erased)++;
            }
        } else {
            (*notchanged)++;
        }
    }
    p->get_stats(&nsr);
    for (e=p->parents ; e ; e=e->nextParent) {
        if(e->parent)
            e->parent->add_sub_stats(&nsr,&psr);
    }
    if (p->mtime!=ts || p->ctime!=ts) {
        p->mtime = p->ctime = ts;
    }
    return STATUS_OK;
}
#else
uint8_t fs_repair(uint32_t ts,uint32_t inode,uint32_t indx,uint32_t nversion) {
    CFsNode *p;
    uint8_t status;
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    if (indx>MAX_INDEX) {
        return ERROR_INDEXTOOBIG;
    }
    if (indx>=p->data.fdata.chunks) {
        return ERROR_NOCHUNK;
    }
    if (p->data.fdata.chunktab[indx]==0) {
        return ERROR_NOCHUNK;
    }
    if (nversion==0) {
        status = CChunkMgr::getInstance()->chunk_delete_file(p->data.fdata.chunktab[indx],p->goal);
        p->data.fdata.chunktab[indx]=0;
    } else {
        status = CChunkMgr::getInstance()->chunk_set_version(p->data.fdata.chunktab[indx],nversion);
    }
    CFileSysMgr::s_MetaVersion++;
    p->mtime = p->ctime = ts;
    return status;
}
#endif

#ifndef METARESTORE
uint8_t fs_getgoal(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint8_t gmode,uint32_t fgtab[10],uint32_t dgtab[10]) {
    CFsNode *p,*rn;
    (void)sesflags;
    memset(fgtab,0,10*sizeof(uint32_t));
    memset(dgtab,0,10*sizeof(uint32_t));
    if (!GMODE_ISVALID(gmode)) {
        return ERROR_EINVAL;
    }
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
    if (p->type!=TYPE_DIRECTORY && p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    fsnodes_getgoal_recursive(p,gmode,fgtab,dgtab);
    return STATUS_OK;
}

uint8_t fs_gettrashtime_prepare(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint8_t gmode,
                                void **fptr,void **dptr,
                                uint32_t *fnodes,uint32_t *dnodes)
{
    CFsNode *p,*rn;
    bstnode *froot,*droot;
    (void)sesflags;
    froot = NULL;
    droot = NULL;
    *fptr = NULL;
    *dptr = NULL;
    *fnodes = 0;
    *dnodes = 0;
    if (!GMODE_ISVALID(gmode)) {
        return ERROR_EINVAL;
    }
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
    if (p->type!=TYPE_DIRECTORY && p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }
    fsnodes_gettrashtime_recursive(p,gmode,&froot,&droot);
    *fptr = froot;
    *dptr = droot;
    *fnodes = fsnodes_bst_nodes(froot);
    *dnodes = fsnodes_bst_nodes(droot);
    return STATUS_OK;
}

void fs_gettrashtime_store(void *fptr,void *dptr,uint8_t *buff) {
    bstnode *froot,*droot;
    froot = (bstnode*)fptr;
    droot = (bstnode*)dptr;
    fsnodes_bst_storedata(froot,&buff);
    fsnodes_bst_storedata(droot,&buff);
    fsnodes_bst_free(froot);
    fsnodes_bst_free(droot);
}

uint8_t fs_geteattr(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint8_t gmode,uint32_t feattrtab[16],uint32_t deattrtab[16])
{
    CFsNode *p,*rn;
    (void)sesflags;
    memset(feattrtab,0,16*sizeof(uint32_t));
    memset(deattrtab,0,16*sizeof(uint32_t));
    if (!GMODE_ISVALID(gmode)) {
        return ERROR_EINVAL;
    }
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
    fsnodes_geteattr_recursive(p,gmode,feattrtab,deattrtab);
    return STATUS_OK;
}

#endif

#ifndef METARESTORE
#if VERSHEX>=0x010700
uint8_t fs_setgoal(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint32_t uid,uint8_t goal,uint8_t smode,uint32_t *sinodes,uint32_t *ncinodes,uint32_t *nsinodes,uint32_t *qeinodes) {
#else
uint8_t fs_setgoal(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint32_t uid,uint8_t goal,uint8_t smode,uint32_t *sinodes,uint32_t *ncinodes,uint32_t *nsinodes) {
#endif
    uint32_t ts;
    CFsNode *rn;
#else
#if VERSHEX>=0x010700
uint8_t fs_setgoal(uint32_t ts,uint32_t inode,uint32_t uid,uint8_t goal,uint8_t smode,uint32_t sinodes,uint32_t ncinodes,uint32_t nsinodes,uint32_t qeinodes) {
    uint32_t si,nci,nsi,qei;
#else
uint8_t fs_setgoal(uint32_t ts,uint32_t inode,uint32_t uid,uint8_t goal,uint8_t smode,uint32_t sinodes,uint32_t ncinodes,uint32_t nsinodes) {
    uint32_t si,nci,nsi;
#endif
#endif
#if VERSHEX>=0x010700
    uint8_t quota;
#endif
    CFsNode *p;

#ifndef METARESTORE
    (void)sesflags;
    ts = CServerCore::get_time();
    *sinodes = 0;
    *ncinodes = 0;
    *nsinodes = 0;
#if VERSHEX>=0x010700
    *qeinodes = 0;
#endif
#else
    si = 0;
    nci = 0;
    nsi = 0;
#if VERSHEX>=0x010700
    qei = 0;
#endif
#endif
    if (!SMODE_ISVALID(smode) || goal>9 || goal<1) {
        return ERROR_EINVAL;
    }
#ifndef METARESTORE
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
#else
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
#endif
    if (p->type!=TYPE_DIRECTORY && p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }

#if VERSHEX>=0x010700
    quota = fsnodes_test_quota(p);
#endif
#ifndef METARESTORE
#if VERSHEX>=0x010700
    fsnodes_setgoal_recursive(p,ts,uid,quota,goal,smode,sinodes,ncinodes,nsinodes,qeinodes);
#else
    fsnodes_setgoal_recursive(p,ts,uid,goal,smode,sinodes,ncinodes,nsinodes);
#endif
    if ((smode&SMODE_RMASK)==0 && *nsinodes>0 && *sinodes==0 && *ncinodes==0) {
        return ERROR_EPERM;
    }
#else
#if VERSHEX>=0x010700
    fsnodes_setgoal_recursive(p,ts,uid,quota,goal,smode,&si,&nci,&nsi,&qei);
#else
    fsnodes_setgoal_recursive(p,ts,uid,goal,smode,&si,&nci,&nsi);
#endif
#endif

#ifndef METARESTORE
#if VERSHEX>=0x010700
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SETGOAL(%"PRIu32",%"PRIu32",%"PRIu8",%"PRIu8"):%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu32,
        ts,inode,uid,goal,smode,*sinodes,*ncinodes,*nsinodes,*qeinodes);
#else
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SETGOAL(%"PRIu32",%"PRIu32",%"PRIu8",%"PRIu8"):%"PRIu32",%"PRIu32",%"PRIu32,
        ts,inode,uid,goal,smode,*sinodes,*ncinodes,*nsinodes);
#endif
    return STATUS_OK;
#else
    CFileSysMgr::s_MetaVersion++;
#if VERSHEX>=0x010700
    if (sinodes!=si || ncinodes!=nci || nsinodes!=nsi || (qeinodes!=qei && qeinodes!=UINT32_C(0xFFFFFFFF))) {
#else
    if (sinodes!=si || ncinodes!=nci || nsinodes!=nsi) {
#endif
        return ERROR_MISMATCH;
    }
    return STATUS_OK;
#endif
}

#ifndef METARESTORE
uint8_t fs_settrashtime(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint32_t uid,uint32_t trashtime,uint8_t smode,uint32_t *sinodes,uint32_t *ncinodes,uint32_t *nsinodes) {
    uint32_t ts;
    CFsNode *rn;
#else
uint8_t fs_settrashtime(uint32_t ts,uint32_t inode,uint32_t uid,uint32_t trashtime,uint8_t smode,uint32_t sinodes,uint32_t ncinodes,uint32_t nsinodes) {
    uint32_t si,nci,nsi;
#endif
    CFsNode *p;

#ifndef METARESTORE
    (void)sesflags;
    ts = CServerCore::get_time();
    *sinodes = 0;
    *ncinodes = 0;
    *nsinodes = 0;
#else
    si = 0;
    nci = 0;
    nsi = 0;
#endif
    if (!SMODE_ISVALID(smode)) {
        return ERROR_EINVAL;
    }
#ifndef METARESTORE
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
#else
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
#endif
    if (p->type!=TYPE_DIRECTORY && p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }

#ifndef METARESTORE
    fsnodes_settrashtime_recursive(p,ts,uid,trashtime,smode,sinodes,ncinodes,nsinodes);
    if ((smode&SMODE_RMASK)==0 && *nsinodes>0 && *sinodes==0 && *ncinodes==0) {
        return ERROR_EPERM;
    }
#else
    fsnodes_settrashtime_recursive(p,ts,uid,trashtime,smode,&si,&nci,&nsi);
#endif

#ifndef METARESTORE
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SETTRASHTIME(%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu8"):%"PRIu32",%"PRIu32",%"PRIu32,ts,inode,uid,trashtime,smode,*sinodes,*ncinodes,*nsinodes);
    return STATUS_OK;
#else
    CFileSysMgr::s_MetaVersion++;
    if (sinodes!=si || ncinodes!=nci || nsinodes!=nsi) {
        return ERROR_MISMATCH;
    }
    return STATUS_OK;
#endif
}

#ifndef METARESTORE
uint8_t fs_seteattr(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint32_t uid,uint8_t eattr,uint8_t smode,uint32_t *sinodes,uint32_t *ncinodes,uint32_t *nsinodes) {
#else
uint8_t fs_seteattr(uint32_t ts,uint32_t inode,uint32_t uid,uint8_t eattr,uint8_t smode,uint32_t sinodes,uint32_t ncinodes,uint32_t nsinodes) {
    uint32_t si,nci,nsi;
#endif

#ifndef METARESTORE
    (void)sesflags;
    uint32_t ts = CServerCore::get_time();
    *sinodes = 0;
    *ncinodes = 0;
    *nsinodes = 0;
#else
    si = 0;
    nci = 0;
    nsi = 0;
#endif
    if (!SMODE_ISVALID(smode) || (eattr&(~(EATTR_NOOWNER|EATTR_NOACACHE|EATTR_NOECACHE|EATTR_NODATACACHE)))) {
        return ERROR_EINVAL;
    }
#ifndef METARESTORE
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    CFsNode *p, *rn;
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
#else
    CFsNode *p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
#endif

#ifndef METARESTORE
    fsnodes_seteattr_recursive(p,ts,uid,eattr,smode,sinodes,ncinodes,nsinodes);
    if ((smode&SMODE_RMASK)==0 && *nsinodes>0 && *sinodes==0 && *ncinodes==0) {
        return ERROR_EPERM;
    }
#else
    fsnodes_seteattr_recursive(p,ts,uid,eattr,smode,&si,&nci,&nsi);
#endif

#ifndef METARESTORE
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SETEATTR(%"PRIu32",%"PRIu32",%"PRIu8",%"PRIu8"):%"PRIu32",%"PRIu32",%"PRIu32/*",%"PRIu32*/,ts,inode,uid,eattr,smode,*sinodes,*ncinodes,*nsinodes/*,*qeinodes*/);
    return STATUS_OK;
#else
    CFileSysMgr::s_MetaVersion++;
    if (sinodes!=si || ncinodes!=nci || nsinodes!=nsi/* || qeinodes!=qei*/) {
        return ERROR_MISMATCH;
    }
    return STATUS_OK;
#endif
}

#ifndef METARESTORE

uint8_t fs_listxattr_leng(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint8_t opened,uint32_t uid,uint32_t gid,void **xanode,uint32_t *xasize)
{
    CFsNode *p,*rn;

    *xasize = 0;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    if (opened==0) {
        if (!fsnodes_access(p,uid,gid,MODE_MASK_R,sesflags)) {
            return ERROR_EACCES;
        }
    }

    return CFsXAttrNode::listattr_leng(inode,xanode,xasize);
}

void fs_listxattr_data(void *xanode,uint8_t *xabuff) {
    CFsXAttrNode *ih = (CFsXAttrNode*)xanode;
    if (ih) {
        uint32_t l = 0;
        CFsXAttrData *xa;
        for (xa=ih->data_head ; xa ; xa=xa->nextinode) {
            memcpy(xabuff+l,xa->attrname,xa->anleng);
            l+=xa->anleng;
            xabuff[l++]=0;
        }
    }
}

uint8_t fs_setxattr(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint8_t opened,
                    uint32_t uid,uint32_t gid,
                    uint8_t anleng,const uint8_t *attrname,
                    uint32_t avleng,const uint8_t *attrvalue,
                    uint8_t mode)
{
    if (sesflags&SESFLAG_READONLY) {
        return ERROR_EROFS;
    }

    CFsNode *p,*rn;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }

        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    if (opened==0) {
        if (!fsnodes_access(p,uid,gid,MODE_MASK_W,sesflags)) {
            return ERROR_EACCES;
        }
    }
    if (xattr_namecheck(anleng,attrname)<0) {
        return ERROR_EINVAL;
    }
    if (mode>MFS_XATTR_REMOVE) {
        return ERROR_EINVAL;
    }
 
    uint8_t status = CFsXAttrNode::setattr(inode,anleng,attrname,avleng,attrvalue,mode);
    if (status!=STATUS_OK) {
        return status;
    }

    uint32_t ts = CServerCore::get_time();
    p->ctime = ts;
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SETXATTR(%"PRIu32",%s,%s,%"PRIu8")",ts,inode,CFsNode::escape_name(anleng,attrname),CFsNode::escape_name(avleng,attrvalue),mode);
    return STATUS_OK;
}

uint8_t fs_getxattr(uint32_t rootinode,uint8_t sesflags,uint32_t inode,uint8_t opened,
                    uint32_t uid,uint32_t gid,
                    uint8_t anleng,const uint8_t *attrname,
                    uint32_t *avleng,uint8_t **attrvalue)
{
    CFsNode *p,*rn;
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }

            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }

    if (opened==0) {
        if (!fsnodes_access(p,uid,gid,MODE_MASK_R,sesflags)) {
            return ERROR_EACCES;
        }
    }
    if (xattr_namecheck(anleng,attrname)<0) {
        return ERROR_EINVAL;
    }
    return CFsXAttrData::getattr(inode,anleng,attrname,avleng,attrvalue);
}

#else /* METARESTORE */

uint8_t fs_setxattr(uint32_t ts,uint32_t inode,
                    uint32_t anleng,const uint8_t *attrname,
                    uint32_t avleng,const uint8_t *attrvalue,
                    uint32_t mode)
{
    CFsNode *p;
    uint8_t status;
    if (anleng==0 || anleng>MFS_XATTR_NAME_MAX || avleng>MFS_XATTR_SIZE_MAX || mode>MFS_XATTR_REMOVE) {
        return ERROR_EINVAL;
    }
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    status = CFsXAttrNode::setattr(inode,anleng,attrname,avleng,attrvalue,mode);

    if (status!=STATUS_OK) {
        return status;
    }
    p->ctime = ts;
    CFileSysMgr::s_MetaVersion++;
    return status;
}

#endif

#ifndef METARESTORE
uint8_t fs_quotacontrol(uint32_t rootinode,uint8_t sesflags,uint32_t inode,
                        uint8_t delflag,uint8_t *flags,
                        uint32_t *sinodes,uint64_t *slength,
                        uint64_t *ssize,uint64_t *srealsize,
                        uint32_t *hinodes,uint64_t *hlength,
                        uint64_t *hsize,uint64_t *hrealsize,
                        uint32_t *curinodes,uint64_t *curlength,
                        uint64_t *cursize,uint64_t *currealsize)
{
    CFsNode *p,*rn;
    CFsQuota *qn;
    STStatsRec *psr;
    uint8_t chg;

    if (*flags) {
        if (sesflags&SESFLAG_READONLY) {
            return ERROR_EROFS;
        }
        if ((sesflags&SESFLAG_CANCHANGEQUOTA)==0) {
            return ERROR_EPERM;
        }
    }
    if (rootinode==0) {
        return ERROR_EPERM;
    }
    if (rootinode==MFS_ROOT_ID) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
    if (p->type!=TYPE_DIRECTORY) {
        return ERROR_EPERM;
    }
    qn = p->data.ddata.quota;
    chg = (*flags)?1:0;
    if (delflag) {
        if (qn) {
            qn->flags &= ~(*flags);
            if (qn->flags==0) {
                chg = 1;
                p->delete_quotanode();
                qn=NULL;
            }
        }
    } else {
        if (qn==NULL && (*flags)!=0) {
            qn = p->new_quotanode();
        }
        if (qn) {
            qn->flags |= *flags;
            if ((*flags)&QUOTA_FLAG_SINODES) {
                qn->sinodes = *sinodes;
            }
            if ((*flags)&QUOTA_FLAG_SLENGTH) {
                qn->slength = *slength;
            }
            if ((*flags)&QUOTA_FLAG_SSIZE) {
                qn->ssize = *ssize;
            }
            if ((*flags)&QUOTA_FLAG_SREALSIZE) {
                qn->srealsize = *srealsize;
            }
            if ((*flags)&QUOTA_FLAG_HINODES) {
                qn->hinodes = *hinodes;
            }
            if ((*flags)&QUOTA_FLAG_HLENGTH) {
                qn->hlength = *hlength;
            }
            if ((*flags)&QUOTA_FLAG_HSIZE) {
                qn->hsize = *hsize;
            }
            if ((*flags)&QUOTA_FLAG_HREALSIZE) {
                qn->hrealsize = *hrealsize;
            }
        }
    }
    if (qn) {
        if (((qn->flags)&QUOTA_FLAG_SINODES)==0) {
            qn->sinodes = 0;
        }
        if (((qn->flags)&QUOTA_FLAG_HINODES)==0) {
            qn->hinodes = 0;
        }
        if (((qn->flags)&QUOTA_FLAG_SLENGTH)==0) {
            qn->slength = 0;
        }
        if (((qn->flags)&QUOTA_FLAG_HLENGTH)==0) {
            qn->hlength = 0;
        }
        if (((qn->flags)&QUOTA_FLAG_SSIZE)==0) {
            qn->ssize = 0;
        }
        if (((qn->flags)&QUOTA_FLAG_HSIZE)==0) {
            qn->hsize = 0;
        }
        if (((qn->flags)&QUOTA_FLAG_SREALSIZE)==0) {
            qn->srealsize = 0;
        }
        if (((qn->flags)&QUOTA_FLAG_HREALSIZE)==0) {
            qn->hrealsize = 0;
        }

        *flags = qn->flags;
        *sinodes = qn->sinodes;
        *slength = qn->slength;
        *ssize = qn->ssize;
        *srealsize = qn->srealsize;
        *hinodes = qn->hinodes;
        *hlength = qn->hlength;
        *hsize = qn->hsize;
        *hrealsize = qn->hrealsize;
    } else {
        *flags = 0;
        *sinodes = 0;
        *slength = 0;
        *ssize = 0;
        *srealsize = 0;
        *hinodes = 0;
        *hlength = 0;
        *hsize = 0;
        *hrealsize = 0;
    }
    psr = p->data.ddata.stats;
    *curinodes = psr->inodes;
    *curlength = psr->length;
    *cursize = psr->size;
    *currealsize = psr->realsize;
#if VERSHEX>=0x010700
    if (chg) {
        if (qn) {
            changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|QUOTA(%"PRIu32",%"PRIu8",%"PRIu8",%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64")",CServerCore::get_time(),inode,qn->exceeded,qn->flags,qn->stimestamp,qn->sinodes,qn->hinodes,qn->slength,qn->hlength,qn->ssize,qn->hsize,qn->srealsize,qn->hrealsize);
        } else {
            changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|QUOTA(%"PRIu32",0,0,0,0,0,0,0,0,0,0,0)",CServerCore::get_time(),inode);
        }
    }
#else
    (void)chg;
#endif
    return STATUS_OK;
}
#else
uint8_t fs_quota(uint32_t ts,uint32_t inode,uint8_t exceeded,uint8_t flags,uint32_t stimestamp,uint32_t sinodes,uint32_t hinodes,uint64_t slength,uint64_t hlength,uint64_t ssize,uint64_t hsize,uint64_t srealsize,uint64_t hrealsize) {
    CFsNode *p;
#if VERSHEX>=0x010700
    CFsQuota *qn;
#endif

    (void)ts;
    p = CFsNode::id_to_node(inode);
    if (!p) {
        return ERROR_ENOENT;
    }
    if (p->type!=TYPE_DIRECTORY) {
        return ERROR_EPERM;
    }
#if VERSHEX>=0x010700
    qn = p->data.ddata.quota;
    if (flags==0) {
        if (qn!=NULL) {
            p->delete_quotanode();
        }
    } else {
        if (qn==NULL) {
            qn = p->new_quotanode();
        }
        qn->flags = flags;
        qn->exceeded = exceeded;
        qn->stimestamp = stimestamp;
        qn->sinodes = sinodes;
        qn->slength = slength;
        qn->ssize = ssize;
        qn->srealsize = srealsize;
        qn->hinodes = hinodes;
        qn->hlength = hlength;
        qn->hsize = hsize;
        qn->hrealsize = hrealsize;
    }
#else
    (void)flags;
    (void)exceeded;
    (void)stimestamp;
    (void)sinodes;
    (void)slength;
    (void)ssize;
    (void)srealsize;
    (void)hinodes;
    (void)hlength;
    (void)hsize;
    (void)hrealsize;
#endif
    CFileSysMgr::s_MetaVersion++;
    return STATUS_OK;
}
#endif

#ifndef METARESTORE
uint32_t fs_getquotainfo_size() {
    CFsQuota *qn;
    uint32_t s=0,size;
    for (qn=CFsQuota::s_quotaHead ; qn ; qn=qn->next) {
        size=qn->node->parents->get_path_size();
        s+=4+4+1+1+4+3*(4+8+8+8)+1+size;
    }

    return s;
}

void fs_getquotainfo_data(uint8_t * buff)
{
    CFsQuota *qn;
    STStatsRec *psr;
    uint32_t size;
    uint32_t ts = CServerCore::get_time();

    for (qn=CFsQuota::s_quotaHead ; qn ; qn=qn->next) {
        psr = qn->node->data.ddata.stats;
        put32bit(&buff,qn->node->id);
        size=qn->node->parents->get_path_size();
        put32bit(&buff,size+1);
        put8bit(&buff,'/');
        qn->node->parents->get_path_data(buff,size);
        buff+=size;
        put8bit(&buff,qn->exceeded);
        put8bit(&buff,qn->flags);
        if (qn->stimestamp==0) {					// soft quota not exceeded
            put32bit(&buff,0xFFFFFFFF); 				// time to block = INF
        } else if (qn->stimestamp+CFsQuota::s_QuotaTimeLimit<ts) {			// soft quota timed out
            put32bit(&buff,0);					// time to block = 0 (blocked)
        } else {							// soft quota exceeded, but not timed out
            put32bit(&buff,qn->stimestamp+CFsQuota::s_QuotaTimeLimit-ts);
        }
        if (qn->flags&QUOTA_FLAG_SINODES) {
            put32bit(&buff,qn->sinodes);
        } else {
            put32bit(&buff,0);
        }
        if (qn->flags&QUOTA_FLAG_SLENGTH) {
            put64bit(&buff,qn->slength);
        } else {
            put64bit(&buff,0);
        }
        if (qn->flags&QUOTA_FLAG_SSIZE) {
            put64bit(&buff,qn->ssize);
        } else {
            put64bit(&buff,0);
        }
        if (qn->flags&QUOTA_FLAG_SREALSIZE) {
            put64bit(&buff,qn->srealsize);
        } else {
            put64bit(&buff,0);
        }
        if (qn->flags&QUOTA_FLAG_HINODES) {
            put32bit(&buff,qn->hinodes);
        } else {
            put32bit(&buff,0);
        }
        if (qn->flags&QUOTA_FLAG_HLENGTH) {
            put64bit(&buff,qn->hlength);
        } else {
            put64bit(&buff,0);
        }
        if (qn->flags&QUOTA_FLAG_HSIZE) {
            put64bit(&buff,qn->hsize);
        } else {
            put64bit(&buff,0);
        }
        if (qn->flags&QUOTA_FLAG_HREALSIZE) {
            put64bit(&buff,qn->hrealsize);
        } else {
            put64bit(&buff,0);
        }
        put32bit(&buff,psr->inodes);
        put64bit(&buff,psr->length);
        put64bit(&buff,psr->size);
        put64bit(&buff,psr->realsize);
    }
}

uint8_t fs_get_dir_stats(uint32_t rootinode,uint8_t sesflags,
                         uint32_t inode,uint32_t *inodes,uint32_t *dirs,uint32_t *files,uint32_t *chunks,uint64_t *length,uint64_t *size,uint64_t *rsize)
{
    CFsNode *p,*rn;
    if (rootinode==MFS_ROOT_ID || rootinode==0) {
        p = CFsNode::id_to_node(inode);
        if (!p) {
            return ERROR_ENOENT;
        }
        if (rootinode==0 && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
            return ERROR_EPERM;
        }
    } else {
        rn = CFsNode::id_to_node(rootinode);
        if (!rn || rn->type!=TYPE_DIRECTORY) {
            return ERROR_ENOENT;
        }
        if (inode==MFS_ROOT_ID) {
            // inode = rootinode;
            p = rn;
        } else {
            p = CFsNode::id_to_node(inode);
            if (!p) {
                return ERROR_ENOENT;
            }
            if (!fsnodes_isancestor(rn,p)) {
                return ERROR_EPERM;
            }
        }
    }
    if (p->type!=TYPE_DIRECTORY && p->type!=TYPE_FILE && p->type!=TYPE_TRASH && p->type!=TYPE_RESERVED) {
        return ERROR_EPERM;
    }

    STStatsRec sr;
    p->get_stats(&sr);
    *inodes = sr.inodes;
    *dirs = sr.dirs;
    *files = sr.files;
    *chunks = sr.chunks;
    *length = sr.length;
    *size = sr.size;
    *rsize = sr.realsize;

    return STATUS_OK;
}
#endif

void fs_add_files_to_chunks() {
    uint32_t i,j;
    uint64_t chunkid;
    CFsNode *f;
    for (i=0 ; i<NODEHASHSIZE ; i++)
    {
        for (f=CFsNode::s_nodehash[i] ; f ; f=f->next)
        {
            if (f->type==TYPE_FILE || f->type==TYPE_TRASH || f->type==TYPE_RESERVED) {
                for (j=0 ; j<f->data.fdata.chunks ; j++) {
                    chunkid = f->data.fdata.chunktab[j];
                    if (chunkid>0) {
                        ChkMgr->chunk_add_file(chunkid,f->goal);
                    }
                }
            }
        }
    }
}

#ifndef METARESTORE

void fs_test_getdata(uint32_t *loopstart,uint32_t *loopend,
                     uint32_t *files,uint32_t *ugfiles,uint32_t *mfiles,
                     uint32_t *chunks,uint32_t *ugchunks,uint32_t *mchunks,
                     char **msgbuff,uint32_t *msgbuffleng) 
{
    *loopstart = fsinfo_loopstart;
    *loopend = fsinfo_loopend;
    *files = fsinfo_files;
    *ugfiles = fsinfo_ugfiles;
    *mfiles = fsinfo_mfiles;
    *chunks = fsinfo_chunks;
    *ugchunks = fsinfo_ugchunks;
    *mchunks = fsinfo_mchunks;
    *msgbuff = fsinfo_msgbuff;
    *msgbuffleng = fsinfo_msgbuffleng;
}

uint32_t fs_test_log_inconsistency(CFsEdge *e,const char *iname,char *buff,uint32_t size)
{
    uint32_t leng;
    leng=0;
    if (e->parent) {
        syslog(LOG_ERR,"structure error - %s inconsistency (edge: %"PRIu32",%s -> %"PRIu32")",iname,e->parent->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
        if (leng<size) {
            leng += snprintf(buff+leng,size-leng,"structure error - %s inconsistency (edge: %"PRIu32",%s -> %"PRIu32")\n",iname,e->parent->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
        }
    } else {
        if (e->child->type==TYPE_TRASH) {
            syslog(LOG_ERR,"structure error - %s inconsistency (edge: TRASH,%s -> %"PRIu32")",iname,CFsNode::escape_name(e->nleng,e->name),e->child->id);
            if (leng<size) {
                leng += snprintf(buff+leng,size-leng,"structure error - %s inconsistency (edge: TRASH,%s -> %"PRIu32")\n",iname,CFsNode::escape_name(e->nleng,e->name),e->child->id);
            }
        } else if (e->child->type==TYPE_RESERVED) {
            syslog(LOG_ERR,"structure error - %s inconsistency (edge: RESERVED,%s -> %"PRIu32")",iname,CFsNode::escape_name(e->nleng,e->name),e->child->id);
            if (leng<size) {
                leng += snprintf(buff+leng,size-leng,"structure error - %s inconsistency (edge: RESERVED,%s -> %"PRIu32")\n",iname,CFsNode::escape_name(e->nleng,e->name),e->child->id);
            }
        } else {
            syslog(LOG_ERR,"structure error - %s inconsistency (edge: NULL,%s -> %"PRIu32")",iname,CFsNode::escape_name(e->nleng,e->name),e->child->id);
            if (leng<size) {
                leng += snprintf(buff+leng,size-leng,"structure error - %s inconsistency (edge: NULL,%s -> %"PRIu32")\n",iname,CFsNode::escape_name(e->nleng,e->name),e->child->id);
            }
        }
    }
    return leng;
}

void fs_test_files()
{
    static uint32_t i=0, leng=0;
    static uint32_t errors=0;
    static uint32_t s_files=0, s_ugFiles=0, s_umFiles=0;
    static uint32_t s_chunks=0, s_ugchunks=0, s_mchunks=0;
    static uint32_t s_notFoundChunks=0, s_unavailChunks=0;
    static uint32_t s_unavailFiles=0, s_unavailTrashFiles=0, s_unavailReservedFiles=0;
    static char *msgbuff=NULL,*tmp;

    if ((uint32_t)(CServerCore::get_time())<=test_start_time) {
        return;
    }
    if (i>=NODEHASHSIZE) {
        syslog(LOG_NOTICE,"structure check loop");
        i=0;
        errors=0;
    }

    if (i==0) {
        if (errors==ERRORS_LOG_MAX) {
            syslog(LOG_ERR,"only first %u errors (unavailable chunks/files) were logged",ERRORS_LOG_MAX);
            if (leng<MSGBUFFSIZE) {
                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"only first %u errors (unavailable chunks/files) were logged\n",ERRORS_LOG_MAX);
            }
        }
        if (s_notFoundChunks>0) {
            syslog(LOG_ERR,"unknown chunks: %"PRIu32,s_notFoundChunks);
            if (leng<MSGBUFFSIZE) {
                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"unknown chunks: %"PRIu32"\n",s_notFoundChunks);
            }
            s_notFoundChunks=0;
        }
        if (s_unavailChunks>0) {
            syslog(LOG_ERR,"unavailable chunks: %"PRIu32,s_unavailChunks);
            if (leng<MSGBUFFSIZE) {
                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"unavailable chunks: %"PRIu32"\n",s_unavailChunks);
            }
            s_unavailChunks=0;
        }
        if (s_unavailTrashFiles>0) {
            syslog(LOG_ERR,"unavailable trash files: %"PRIu32,s_unavailTrashFiles);
            if (leng<MSGBUFFSIZE) {
                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"unavailable trash files: %"PRIu32"\n",s_unavailTrashFiles);
            }
            s_unavailTrashFiles=0;
        }
        if (s_unavailReservedFiles>0) {
            syslog(LOG_ERR,"unavailable reserved files: %"PRIu32,s_unavailReservedFiles);
            if (leng<MSGBUFFSIZE) {
                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"unavailable reserved files: %"PRIu32"\n",s_unavailReservedFiles);
            }
            s_unavailReservedFiles=0;
        }
        if (s_unavailFiles>0) {
            syslog(LOG_ERR,"unavailable files: %"PRIu32,s_unavailFiles);
            if (leng<MSGBUFFSIZE) {
                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"unavailable files: %"PRIu32"\n",s_unavailFiles);
            }
            s_unavailFiles=0;
        }

        fsinfo_files=s_files;
        fsinfo_ugfiles=s_ugFiles;
        fsinfo_mfiles=s_umFiles;
        fsinfo_chunks=s_chunks;
        fsinfo_ugchunks=s_ugchunks;
        fsinfo_mchunks=s_mchunks;
        s_files=s_ugFiles=s_umFiles=s_chunks=s_ugchunks=s_mchunks=0;

        if (fsinfo_msgbuff==NULL) {
            fsinfo_msgbuff=(char*)malloc(MSGBUFFSIZE);
            passert(fsinfo_msgbuff);
        }
        tmp = fsinfo_msgbuff;
        fsinfo_msgbuff=msgbuff;
        msgbuff = tmp;
        if (leng>MSGBUFFSIZE) {
            fsinfo_msgbuffleng=MSGBUFFSIZE;
        } else {
            fsinfo_msgbuffleng=leng;
        }
        leng=0;

        fsinfo_loopstart = fsinfo_loopend;
        fsinfo_loopend = CServerCore::get_time();
    }

    uint32_t j, k;
    uint64_t chunkid;
    uint8_t vc,valid,ugflag;
    CFsNode *f;
    CFsEdge *e;
    for (k=0 ; k<(NODEHASHSIZE/14400) && i<NODEHASHSIZE ; k++,i++)
    {
        for (f=CFsNode::s_nodehash[i] ; f ; f=f->next)
        {
            if (f->type==TYPE_FILE || f->type==TYPE_TRASH || f->type==TYPE_RESERVED)
            {
                valid = 1;
                ugflag = 0;
                for (j=0 ; j<f->data.fdata.chunks ; j++) {
                    chunkid = f->data.fdata.chunktab[j];
                    if (chunkid>0) {
                        if (ChkMgr->chunk_get_validcopies(chunkid,&vc)!=STATUS_OK) {
                            if (errors<ERRORS_LOG_MAX) {
                                syslog(LOG_ERR,"structure error - chunk %016"PRIX64" not found (inode: %"PRIu32" ; index: %"PRIu32")",chunkid,f->id,j);
                                if (leng<MSGBUFFSIZE) {
                                    leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"structure error - chunk %016"PRIX64" not found (inode: %"PRIu32" ; index: %"PRIu32")\n",chunkid,f->id,j);
                                }
                                errors++;
                            }
                            s_notFoundChunks++;
                            if ((s_notFoundChunks%1000)==0) {
                                syslog(LOG_ERR,"unknown chunks: %"PRIu32" ...",s_notFoundChunks);
                            }
                            valid =0;
                            s_mchunks++;
                        } else if (vc==0) {
                            if (errors<ERRORS_LOG_MAX) {
                                syslog(LOG_ERR,"currently unavailable chunk %016"PRIX64" (inode: %"PRIu32" ; index: %"PRIu32")",chunkid,f->id,j);
                                if (leng<MSGBUFFSIZE) {
                                    leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"currently unavailable chunk %016"PRIX64" (inode: %"PRIu32" ; index: %"PRIu32")\n",chunkid,f->id,j);
                                }
                                errors++;
                            }
                            s_unavailChunks++;
                            if ((s_unavailChunks%1000)==0) {
                                syslog(LOG_ERR,"unavailable chunks: %"PRIu32" ...",s_unavailChunks);
                            }
                            valid = 0;
                            s_mchunks++;
                        } else if (vc<f->goal) {
                            ugflag = 1;
                            s_ugchunks++;
                        }
                        s_chunks++;
                    }
                }

                if (valid==0) {
                    s_umFiles++;
                    if (f->type==TYPE_TRASH) {
                        if (errors<ERRORS_LOG_MAX) {
                            syslog(LOG_ERR,"- currently unavailable file in trash %"PRIu32": %s",f->id,CFsNode::escape_name(f->parents->nleng,f->parents->name));
                            if (leng<MSGBUFFSIZE) {
                                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"- currently unavailable file in trash %"PRIu32": %s\n",f->id,CFsNode::escape_name(f->parents->nleng,f->parents->name));
                            }
                            errors++;
                            s_unavailTrashFiles++;
                            if ((s_unavailTrashFiles%1000)==0) {
                                syslog(LOG_ERR,"unavailable trash files: %"PRIu32" ...",s_unavailTrashFiles);
                            }
                        }
                    } else if (f->type==TYPE_RESERVED) {
                        if (errors<ERRORS_LOG_MAX) {
                            syslog(LOG_ERR,"+ currently unavailable reserved file %"PRIu32": %s",f->id,CFsNode::escape_name(f->parents->nleng,f->parents->name));
                            if (leng<MSGBUFFSIZE) {
                                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"+ currently unavailable reserved file %"PRIu32": %s\n",f->id,CFsNode::escape_name(f->parents->nleng,f->parents->name));
                            }
                            errors++;
                            s_unavailReservedFiles++;
                            if ((s_unavailReservedFiles%1000)==0) {
                                syslog(LOG_ERR,"unavailable reserved files: %"PRIu32" ...",s_unavailReservedFiles);
                            }
                        }
                    } else {
                        uint8_t *path;
                        uint16_t pleng;
                        for (e=f->parents ; e ; e=e->nextParent) {
                            if (errors<ERRORS_LOG_MAX) {
                                e->get_path(&pleng,&path);
                                syslog(LOG_ERR,"* currently unavailable file %"PRIu32": %s",f->id,CFsNode::escape_name(pleng,path));
                                if (leng<MSGBUFFSIZE) {
                                    leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"* currently unavailable file %"PRIu32": %s\n",f->id,CFsNode::escape_name(pleng,path));
                                }
                                free(path);
                                errors++;
                            }

                            s_unavailFiles++;
                            if ((s_unavailFiles%1000)==0) {
                                syslog(LOG_ERR,"unavailable files: %"PRIu32" ...",s_unavailFiles);
                            }
                        }
                    }
                } else if (ugflag) {
                    s_ugFiles++;
                }
                s_files++;
            }

            for (e=f->parents ; e ; e=e->nextParent) {
                if (e->child != f) {
                    if (e->parent) {
                        syslog(LOG_ERR,"structure error - edge->child/child->edges (node: %"PRIu32" ; edge: %"PRIu32",%s -> %"PRIu32")",f->id,e->parent->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
                        if (leng<MSGBUFFSIZE) {
                            leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"structure error - edge->child/child->edges (node: %"PRIu32" ; edge: %"PRIu32",%s -> %"PRIu32")\n",f->id,e->parent->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
                        }
                    } else {
                        syslog(LOG_ERR,"structure error - edge->child/child->edges (node: %"PRIu32" ; edge: NULL,%s -> %"PRIu32")",f->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
                        if (leng<MSGBUFFSIZE) {
                            leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"structure error - edge->child/child->edges (node: %"PRIu32" ; edge: NULL,%s -> %"PRIu32")\n",f->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
                        }
                    }
                } else if (e->nextChild) {
                    if (e->nextChild->prevChild != &(e->nextChild)) {
                        if (leng<MSGBUFFSIZE) {
                            leng += fs_test_log_inconsistency(e,"nextChild/prevChild",msgbuff+leng,MSGBUFFSIZE-leng);
                        } else {
                            fs_test_log_inconsistency(e,"nextChild/prevChild",NULL,0);
                        }
                    }
                } else if (e->nextParent) {
                    if (e->nextParent->prevParent != &(e->nextParent)) {
                        if (leng<MSGBUFFSIZE) {
                            leng += fs_test_log_inconsistency(e,"nextParent/prevParent",msgbuff+leng,MSGBUFFSIZE-leng);
                        } else {
                            fs_test_log_inconsistency(e,"nextParent/prevParent",NULL,0);
                        }
                    }
#ifdef EDGEHASH
                } else if (e->next) {
                    if (e->next->prev != &(e->next)) {
                        if (leng<MSGBUFFSIZE) {
                            leng += fs_test_log_inconsistency(e,"nexthash/prevhash",msgbuff+leng,MSGBUFFSIZE-leng);
                        } else {
                            fs_test_log_inconsistency(e,"nexthash/prevhash",NULL,0);
                        }
                    }
#endif
                }
            }//end for

            if (f->type == TYPE_DIRECTORY) {
                for (e=f->data.ddata.children ; e ; e=e->nextChild) {
                    if (e->parent != f) {
                        if (e->parent) {
                            syslog(LOG_ERR,"structure error - edge->parent/parent->edges (node: %"PRIu32" ; edge: %"PRIu32",%s -> %"PRIu32")",f->id,e->parent->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
                            if (leng<MSGBUFFSIZE) {
                                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"structure error - edge->parent/parent->edges (node: %"PRIu32" ; edge: %"PRIu32",%s -> %"PRIu32")\n",f->id,e->parent->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
                            }
                        } else {
                            syslog(LOG_ERR,"structure error - edge->parent/parent->edges (node: %"PRIu32" ; edge: NULL,%s -> %"PRIu32")",f->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
                            if (leng<MSGBUFFSIZE) {
                                leng += snprintf(msgbuff+leng,MSGBUFFSIZE-leng,"structure error - edge->parent/parent->edges (node: %"PRIu32" ; edge: NULL,%s -> %"PRIu32")\n",f->id,CFsNode::escape_name(e->nleng,e->name),e->child->id);
                            }
                        }
                    } else if (e->nextChild) {
                        if (e->nextChild->prevChild != &(e->nextChild)) {
                            if (leng<MSGBUFFSIZE) {
                                leng += fs_test_log_inconsistency(e,"nextChild/prevChild",msgbuff+leng,MSGBUFFSIZE-leng);
                            } else {
                                fs_test_log_inconsistency(e,"nextChild/prevChild",NULL,0);
                            }
                        }
                    } else if (e->nextParent) {
                        if (e->nextParent->prevParent != &(e->nextParent)) {
                            if (leng<MSGBUFFSIZE) {
                                leng += fs_test_log_inconsistency(e,"nextParent/prevParent",msgbuff+leng,MSGBUFFSIZE-leng);
                            } else {
                                fs_test_log_inconsistency(e,"nextParent/prevParent",NULL,0);
                            }
                        }
#ifdef EDGEHASH
                    } else if (e->next) {
                        if (e->next->prev != &(e->next)) {
                            if (leng<MSGBUFFSIZE) {
                                leng += fs_test_log_inconsistency(e,"nexthash/prevhash",msgbuff+leng,MSGBUFFSIZE-leng);
                            } else {
                                fs_test_log_inconsistency(e,"nexthash/prevhash",NULL,0);
                            }
                        }
#endif
                    }
                }//end for
            }//end if
        }
    }
}
#endif


#ifndef METARESTORE
void fs_emptytrash(void) {
#else
uint8_t fs_emptytrash(uint32_t ts,uint32_t freeinodes,uint32_t reservedinodes) {
#endif
    uint32_t fi=0,ri=0;
    CFsEdge *e = CFsEdge::s_trash;
    CFsNode *p;
#ifndef METARESTORE
    uint32_t ts = CServerCore::get_time();
#endif
    while (e) {
        p = e->child;
        e = e->nextChild;
        if (((uint64_t)(p->atime) + (uint64_t)(p->trashtime) < (uint64_t)ts) && ((uint64_t)(p->mtime) + (uint64_t)(p->trashtime) < (uint64_t)ts) && ((uint64_t)(p->ctime) + (uint64_t)(p->trashtime) < (uint64_t)ts)) {
            if (fsnodes_purge(ts,p)) {
                fi++;
            } else {
                ri++;
            }
        }
    }
#ifndef METARESTORE
    if ((fi|ri)>0) {
        changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|EMPTYTRASH():%"PRIu32",%"PRIu32,ts,fi,ri);
    }
#else
    CFileSysMgr::s_MetaVersion++;
    if (freeinodes!=fi || reservedinodes!=ri) {
        return ERROR_MISMATCH;
    }
    return STATUS_OK;
#endif
}

#ifndef METARESTORE
void fs_emptyreserved(void) {
    uint32_t ts;
#else
uint8_t fs_emptyreserved(uint32_t ts,uint32_t freeinodes) {
#endif
    CFsEdge *e;
    CFsNode *p;
    uint32_t fi;
#ifndef METARESTORE
    ts = CServerCore::get_time();
#endif
    fi=0;
    e = CFsEdge::s_reserved;
    while (e) {
        p = e->child;
        e = e->nextChild;
        if (p->data.fdata.sessIDs==NULL) {
            fsnodes_purge(ts,p);
            fi++;
        }
    }
#ifndef METARESTORE
    if (fi>0) {
        changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|EMPTYRESERVED():%"PRIu32,ts,fi);
    }
#else
    CFileSysMgr::s_MetaVersion++;
    if (freeinodes!=fi) {
        return ERROR_MISMATCH;
    }
    return STATUS_OK;
#endif
}


#ifdef METARESTORE

uint64_t fs_getversion() {
    return CFileSysMgr::s_MetaVersion;
}

#endif

enum {FLAG_TREE,FLAG_TRASH,FLAG_RESERVED};

#ifdef METARESTORE
/* DUMP */

void fs_dumpedgelist(CFsEdge *e) {
    while (e) {
        e->dump();
        e=e->nextChild;
    }
}

void fs_dumpedges(CFsNode *f) {
    CFsEdge *e;
    fs_dumpedgelist(f->data.ddata.children);
    for (e=f->data.ddata.children ; e ; e=e->nextChild) {
        if (e->child->type==TYPE_DIRECTORY) {
            e->child->dump();
        }
    }
}

void fs_dump(void) {
    CFsNode::dumpnodes();
    fs_dumpedges(CFsNode::s_root);
    fs_dumpedgelist(CFsEdge::s_trash);
    fs_dumpedgelist(CFsEdge::s_reserved);
    CFileIDMgr::dumpfree();
    CFsXAttrData::xattr_dump();
}

#endif

void fs_storeedge(CFsEdge *e,FILE *fd) {
    uint8_t uedgebuff[4+4+2+65535];
    uint8_t *ptr;
    if (e==NULL) {	// last edge
        memset(uedgebuff,0,4+4+2);
        if (fwrite(uedgebuff,1,4+4+2,fd)!=(size_t)(4+4+2)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        return;
    }
    ptr = uedgebuff;
    if (e->parent==NULL) {
        put32bit(&ptr,0);
    } else {
        put32bit(&ptr,e->parent->id);
    }
    put32bit(&ptr,e->child->id);
    put16bit(&ptr,e->nleng);
    memcpy(ptr,e->name,e->nleng);
    if (fwrite(uedgebuff,1,4+4+2+e->nleng,fd)!=(size_t)(4+4+2+e->nleng)) {
        syslog(LOG_NOTICE,"fwrite error");
        return;
    }
}

int fs_loadedge(FILE *fd,int ignoreflag) {
    uint8_t uedgebuff[4+4+2];
    const uint8_t *ptr;
    uint32_t parent_id;
    uint32_t child_id;
#ifdef EDGEHASH
    uint32_t hpos;
#endif
    CFsEdge *e;
#ifndef METARESTORE
    STStatsRec sr;
#endif
    static CFsEdge **root_tail;
    static CFsEdge **current_tail;
    static uint32_t current_parent_id;
    static uint8_t nl;

    if (fd==NULL) {
        current_parent_id = 0;
        current_tail = NULL;
        root_tail = NULL;
        nl = 1;
        return 0;
    }

    if (fread(uedgebuff,1,4+4+2,fd)!=4+4+2) {
        int err = errno;
        if (nl) {
            fputc('\n',stderr);
            nl=0;
        }
        errno = err;
        mfs_errlog(LOG_ERR,"loading edge: read error");
        return -1;
    }
    ptr = uedgebuff;
    parent_id = get32bit(&ptr);
    child_id = get32bit(&ptr);
    if (parent_id==0 && child_id==0) {	// last edge
        return 1;
    }
    e = (CFsEdge*)malloc(sizeof(CFsEdge));
    passert(e);
    e->nleng = get16bit(&ptr);
    if (e->nleng==0) {
        if (nl) {
            fputc('\n',stderr);
            nl=0;
        }
        mfs_arg_syslog(LOG_ERR,"loading edge: %"PRIu32"->%"PRIu32" error: empty name",parent_id,child_id);
        free(e);
        return -1;
    }
    e->name = (uint8_t*)malloc(e->nleng);
    passert(e->name);
    if (fread(e->name,1,e->nleng,fd)!=e->nleng) {
        int err = errno;
        if (nl) {
            fputc('\n',stderr);
            nl=0;
        }
        errno = err;
        mfs_errlog(LOG_ERR,"loading edge: read error");
        free(e->name);
        free(e);
        return -1;
    }
    e->child = CFsNode::id_to_node(child_id);
    if (e->child==NULL) {
        if (nl) {
            fputc('\n',stderr);
            nl=0;
        }
        mfs_arg_syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" error: child not found",
            parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
        free(e->name);
        free(e);
        if (ignoreflag) {
            return 0;
        }
        return -1;
    }
    if (parent_id==0) {
        if (e->child->type==TYPE_TRASH) {
            e->parent = NULL;
            e->nextChild = CFsEdge::s_trash;
            if (e->nextChild) {
                e->nextChild->prevChild = &(e->nextChild);
            }
            CFsEdge::s_trash = e;
            e->prevChild = &CFsEdge::s_trash;
#ifdef EDGEHASH
            e->next = NULL;
            e->prev = NULL;
#endif
            CFileSysMgr::s_trashspace += e->child->data.fdata.length;
            CFileSysMgr::s_trashnodes++;
        } else if (e->child->type==TYPE_RESERVED) {
            e->parent = NULL;
            e->nextChild = CFsEdge::s_reserved;
            if (e->nextChild) {
                e->nextChild->prevChild = &(e->nextChild);
            }
            CFsEdge::s_reserved = e;
            e->prevChild = &CFsEdge::s_reserved;
#ifdef EDGEHASH
            e->next = NULL;
            e->prev = NULL;
#endif
            CFileSysMgr::s_reservedspace += e->child->data.fdata.length;
            CFileSysMgr::s_reservednodes++;
        } else {
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            fprintf(stderr,"loading edge: %"PRIu32",%s->%"PRIu32" error: bad child type (%c)\n",
                parent_id,CFsNode::escape_name(e->nleng,e->name),child_id,e->child->type);
#ifndef METARESTORE
            syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" error: bad child type (%c)",
                parent_id,CFsNode::escape_name(e->nleng,e->name),child_id,e->child->type);
#endif
            free(e->name);
            free(e);
            return -1;
        }
    } else {
        e->parent = CFsNode::id_to_node(parent_id);
        if (e->parent==NULL) {
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            fprintf(stderr,"loading edge: %"PRIu32",%s->%"PRIu32" error: parent not found\n",
                parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#ifndef METARESTORE
            syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" error: parent not found",
                parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#endif
            if (ignoreflag) {
                e->parent = CFsNode::id_to_node(MFS_ROOT_ID);
                if (e->parent==NULL || e->parent->type!=TYPE_DIRECTORY) {
                    fprintf(stderr,"loading edge: %"PRIu32",%s->%"PRIu32" root dir not found !!!\n",
                        parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#ifndef METARESTORE
                    syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" root dir not found !!!",
                        parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#endif
                    free(e->name);
                    free(e);
                    return -1;
                }
                fprintf(stderr,"loading edge: %"PRIu32",%s->%"PRIu32" attaching node to root dir\n",
                    parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#ifndef METARESTORE
                syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" attaching node to root dir",
                    parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#endif
                parent_id = MFS_ROOT_ID;
            } else {
                fprintf(stderr,"use mfsmetarestore (option -i) to attach this node to root dir\n");
                free(e->name);
                free(e);
                return -1;
            }
        }
        if (e->parent->type!=TYPE_DIRECTORY) {
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            fprintf(stderr,"loading edge: %"PRIu32",%s->%"PRIu32" error: bad parent type (%c)\n",
                parent_id,CFsNode::escape_name(e->nleng,e->name),child_id,e->parent->type);
#ifndef METARESTORE
            syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" error: bad parent type (%c)",
                parent_id,CFsNode::escape_name(e->nleng,e->name),child_id,e->parent->type);
#endif
            if (ignoreflag) {
                e->parent = CFsNode::id_to_node(MFS_ROOT_ID);
                if (e->parent==NULL || e->parent->type!=TYPE_DIRECTORY) {
                    fprintf(stderr,"loading edge: %"PRIu32",%s->%"PRIu32" root dir not found !!!\n",
                        parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#ifndef METARESTORE
                    syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" root dir not found !!!",
                        parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#endif
                    free(e->name);
                    free(e);
                    return -1;
                }
                fprintf(stderr,"loading edge: %"PRIu32",%s->%"PRIu32" attaching node to root dir\n",
                    parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#ifndef METARESTORE
                syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" attaching node to root dir",
                    parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#endif
                parent_id = MFS_ROOT_ID;
            } else {
                fprintf(stderr,"use mfsmetarestore (option -i) to attach this node to root dir\n");
                free(e->name);
                free(e);
                return -1;
            }
        }
        if (parent_id==MFS_ROOT_ID) {	// special case - because of 'ignoreflag' and possibility of attaching orphans into root node
            if (root_tail==NULL) {
                root_tail = &(e->parent->data.ddata.children);
            }
        } else if (current_parent_id!=parent_id) {
            if (e->parent->data.ddata.children) {
                if (nl) {
                    fputc('\n',stderr);
                    nl=0;
                }
                fprintf(stderr,"loading edge: %"PRIu32",%s->%"PRIu32" error: parent node sequence error\n",
                    parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#ifndef METARESTORE
                syslog(LOG_ERR,"loading edge: %"PRIu32",%s->%"PRIu32" error: parent node sequence error",
                    parent_id,CFsNode::escape_name(e->nleng,e->name),child_id);
#endif
                if (ignoreflag) {
                    current_tail = &(e->parent->data.ddata.children);
                    while (*current_tail) {
                        current_tail = &((*current_tail)->nextChild);
                    }
                } else {
                    free(e->name);
                    free(e);
                    return -1;
                }
            } else {
                current_tail = &(e->parent->data.ddata.children);
            }
            current_parent_id = parent_id;
        }
        e->nextChild = NULL;
        if (parent_id==MFS_ROOT_ID) {
            *(root_tail) = e;
            e->prevChild = root_tail;
            root_tail = &(e->nextChild);
        } else {
            *(current_tail) = e;
            e->prevChild = current_tail;
            current_tail = &(e->nextChild);
        }
        e->parent->data.ddata.elements++;
        if (e->child->type==TYPE_DIRECTORY) {
            e->parent->data.ddata.nlink++;
        }
#ifdef EDGEHASH
        hpos = EDGEHASHPOS(CFsNode::fsnodes_hash(e->parent->id,e->nleng,e->name));
        e->next = CFsEdge::s_edgehash[hpos];
        if (e->next) {
            e->next->prev = &(e->next);
        }
        CFsEdge::s_edgehash[hpos] = e;
        e->prev = &(CFsEdge::s_edgehash[hpos]);
#endif
    }
    e->nextParent = e->child->parents;
    if (e->nextParent) {
        e->nextParent->prevParent = &(e->nextParent);
    }
    e->child->parents = e;
    e->prevParent = &(e->child->parents);
#ifndef METARESTORE
    if (e->parent) {
        e->child->get_stats(&sr);
        e->parent->add_stats(&sr);
    }
#endif
    return 0;
}

void fs_storenode(CFsNode *f,FILE *fd) {
    uint8_t unodebuff[1+4+1+2+4+4+4+4+4+4+8+4+2+8*65536+4*65536+4];
    uint8_t *ptr,*chptr;
    uint32_t i,indx,ch,sessIDs;
    STSIDRec *sIDPtr;

    if (f==NULL) {	// last node
        fputc(0,fd);
        return;
    }
    ptr = unodebuff;
    put8bit(&ptr,f->type);
    put32bit(&ptr,f->id);
    put8bit(&ptr,f->goal);
    put16bit(&ptr,f->mode);
    put32bit(&ptr,f->uid);
    put32bit(&ptr,f->gid);
    put32bit(&ptr,f->atime);
    put32bit(&ptr,f->mtime);
    put32bit(&ptr,f->ctime);
    put32bit(&ptr,f->trashtime);

    switch (f->type) {
    case TYPE_DIRECTORY:
    case TYPE_SOCKET:
    case TYPE_FIFO:
        if (fwrite(unodebuff,1,1+4+1+2+4+4+4+4+4+4,fd)!=(size_t)(1+4+1+2+4+4+4+4+4+4)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        break;
    case TYPE_BLOCKDEV:
    case TYPE_CHARDEV:
        put32bit(&ptr,f->data.devdata.rdev);
        if (fwrite(unodebuff,1,1+4+1+2+4+4+4+4+4+4+4,fd)!=(size_t)(1+4+1+2+4+4+4+4+4+4+4)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        break;
    case TYPE_SYMLINK:
        put32bit(&ptr,f->data.sdata.pleng);
        if (fwrite(unodebuff,1,1+4+1+2+4+4+4+4+4+4+4,fd)!=(size_t)(1+4+1+2+4+4+4+4+4+4+4)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        if (fwrite(f->data.sdata.path,1,f->data.sdata.pleng,fd)!=(size_t)(f->data.sdata.pleng)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        break;
    case TYPE_FILE:
    case TYPE_TRASH:
    case TYPE_RESERVED:
        put64bit(&ptr,f->data.fdata.length);
        ch = 0;
        for (indx=0 ; indx<f->data.fdata.chunks ; indx++) {
            if (f->data.fdata.chunktab[indx]!=0) {
                ch=indx+1;
            }
        }
        put32bit(&ptr,ch);
        sessIDs=0;
        for (sIDPtr=f->data.fdata.sessIDs ; sIDPtr && sessIDs<65535; sIDPtr=sIDPtr->next) {
            sessIDs++;
        }
        put16bit(&ptr,sessIDs);

        if (fwrite(unodebuff,1,1+4+1+2+4+4+4+4+4+4+8+4+2,fd)!=(size_t)(1+4+1+2+4+4+4+4+4+4+8+4+2)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }

        indx = 0;
        while (ch>65536) {
            chptr = ptr;
            for (i=0 ; i<65536 ; i++) {
                put64bit(&chptr,f->data.fdata.chunktab[indx]);
                indx++;
            }
            if (fwrite(ptr,1,8*65536,fd)!=(size_t)(8*65536)) {
                syslog(LOG_NOTICE,"fwrite error");
                return;
            }
            ch-=65536;
        }

        chptr = ptr;
        for (i=0 ; i<ch ; i++) {
            put64bit(&chptr,f->data.fdata.chunktab[indx]);
            indx++;
        }

        sessIDs=0;
        for (sIDPtr=f->data.fdata.sessIDs ; sIDPtr && sessIDs<65535; sIDPtr=sIDPtr->next) {
            put32bit(&chptr,sIDPtr->sessionid);
            sessIDs++;
        }

        if (fwrite(ptr,1,8*ch+4*sessIDs,fd)!=(size_t)(8*ch+4*sessIDs)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
    }
}

int fs_loadnode(FILE *fd) {
    uint8_t unodebuff[4+1+2+4+4+4+4+4+4+8+4+2+8*65536+4*65536+4];
    const uint8_t *ptr,*chptr;
    uint8_t type;
    uint32_t i,indx,pleng,ch,sessIDs,sessionid;
    STSIDRec *sIDPtr;
    uint32_t nodepos;
#ifndef METARESTORE
    STStatsRec *sr;
#endif
    static uint8_t nl;

    if (fd==NULL) {
        nl=1;
        return 0;
    }

    type = fgetc(fd);
    if (type==0) {	// last node
        return 1;
    }

    CFsNode *p = (CFsNode*)malloc(sizeof(CFsNode));
    passert(p);
    p->type = type;

    switch (type) {
    case TYPE_DIRECTORY:
    case TYPE_FIFO:
    case TYPE_SOCKET:
        if (fread(unodebuff,1,4+1+2+4+4+4+4+4+4,fd)!=4+1+2+4+4+4+4+4+4) {
            int err = errno;
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            errno = err;
            mfs_errlog(LOG_ERR,"loading node: read error");
            free(p);
            return -1;
        }
        break;
    case TYPE_BLOCKDEV:
    case TYPE_CHARDEV:
    case TYPE_SYMLINK:
        if (fread(unodebuff,1,4+1+2+4+4+4+4+4+4+4,fd)!=4+1+2+4+4+4+4+4+4+4) {
            int err = errno;
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            errno = err;
            mfs_errlog(LOG_ERR,"loading node: read error");
            free(p);
            return -1;
        }
        break;
    case TYPE_FILE:
    case TYPE_TRASH:
    case TYPE_RESERVED:
        if (fread(unodebuff,1,4+1+2+4+4+4+4+4+4+8+4+2,fd)!=4+1+2+4+4+4+4+4+4+8+4+2) {
            int err = errno;
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            errno = err;
            mfs_errlog(LOG_ERR,"loading node: read error");
            free(p);
            return -1;
        }
        break;
    default:
        if (nl) {
            fputc('\n',stderr);
            nl=0;
        }
        mfs_arg_syslog(LOG_ERR,"loading node: unrecognized node type: %c",type);
        free(p);
        return -1;
    }
    ptr = unodebuff;
    p->id = get32bit(&ptr);
    p->goal = get8bit(&ptr);
    p->mode = get16bit(&ptr);
    p->uid = get32bit(&ptr);
    p->gid = get32bit(&ptr);
    p->atime = get32bit(&ptr);
    p->mtime = get32bit(&ptr);
    p->ctime = get32bit(&ptr);
    p->trashtime = get32bit(&ptr);
    switch (type) {
    case TYPE_DIRECTORY:
#ifndef METARESTORE
        sr = (STStatsRec*)malloc(sizeof(STStatsRec));
        passert(sr);
        memset(sr,0,sizeof(STStatsRec));
        p->data.ddata.stats = sr;
#endif
        p->data.ddata.quota = NULL;
        p->data.ddata.children = NULL;
        p->data.ddata.nlink = 2;
        p->data.ddata.elements = 0;
    case TYPE_SOCKET:
    case TYPE_FIFO:
        break;
    case TYPE_BLOCKDEV:
    case TYPE_CHARDEV:
        p->data.devdata.rdev = get32bit(&ptr);
        break;
    case TYPE_SYMLINK:
        pleng = get32bit(&ptr);
        p->data.sdata.pleng = pleng;
        if (pleng>0) {
            p->data.sdata.path = (uint8_t*)malloc(pleng);
            passert(p->data.sdata.path);
            if (fread(p->data.sdata.path,1,pleng,fd)!=pleng) {
                int err = errno;
                if (nl) {
                    fputc('\n',stderr);
                    nl=0;
                }
                errno = err;
                mfs_errlog(LOG_ERR,"loading node: read error");
                free(p->data.sdata.path);
                free(p);
                return -1;
            }
        } else {
            p->data.sdata.path = NULL;
        }
        break;
    case TYPE_FILE:
    case TYPE_TRASH:
    case TYPE_RESERVED:
        p->data.fdata.length = get64bit(&ptr);
        ch = get32bit(&ptr);
        p->data.fdata.chunks = ch;
        sessIDs = get16bit(&ptr);
        if (ch>0) {
            p->data.fdata.chunktab = (uint64_t*)malloc(sizeof(uint64_t)*ch);
            passert(p->data.fdata.chunktab);
        } else {
            p->data.fdata.chunktab = NULL;
        }
        indx = 0;
        while (ch>65536) {
            chptr = ptr;
            if (fread((uint8_t*)ptr,1,8*65536,fd)!=8*65536) {
                int err = errno;
                if (nl) {
                    fputc('\n',stderr);
                    nl=0;
                }
                errno = err;
                mfs_errlog(LOG_ERR,"loading node: read error");
                if (p->data.fdata.chunktab) {
                    free(p->data.fdata.chunktab);
                }
                free(p);
                return -1;
            }
            for (i=0 ; i<65536 ; i++) {
                p->data.fdata.chunktab[indx] = get64bit(&chptr);
                indx++;
            }
            ch-=65536;
        }
        if (fread((uint8_t*)ptr,1,8*ch+4*sessIDs,fd)!=8*ch+4*sessIDs) {
            int err = errno;
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            errno = err;
            mfs_errlog(LOG_ERR,"loading node: read error");
            if (p->data.fdata.chunktab) {
                free(p->data.fdata.chunktab);
            }
            free(p);
            return -1;
        }
        for (i=0 ; i<ch ; i++) {
            p->data.fdata.chunktab[indx] = get64bit(&ptr);
            indx++;
        }
        p->data.fdata.sessIDs=NULL;
        while (sessIDs) {
            sessionid = get32bit(&ptr);
            sIDPtr = sessionidrec_malloc();
            sIDPtr->sessionid = sessionid;
            sIDPtr->next = p->data.fdata.sessIDs;
            p->data.fdata.sessIDs = sIDPtr;
#ifndef METARESTORE
            CClientConn::init_sessions(sessionid,p->id);
#endif
            sessIDs--;
        }
    }

    p->parents = NULL;
    nodepos = NODEHASHPOS(p->id);
    p->next = CFsNode::s_nodehash[nodepos];
    CFsNode::s_nodehash[nodepos] = p;
    CFileIDMgr::getInstance()->used_inode(p->id);
    CFileSysMgr::s_nodes++;
    if (type==TYPE_DIRECTORY) {
        CFileSysMgr::s_dirnodes++;
    }
    if (type==TYPE_FILE || type==TYPE_TRASH || type==TYPE_RESERVED) {
        CFileSysMgr::s_filenodes++;
    }
    return 0;
}

void fs_storenodes(FILE *fd) {
    uint32_t i;
    CFsNode *p;
    for (i=0 ; i<NODEHASHSIZE ; i++) {
        for (p=CFsNode::s_nodehash[i] ; p ; p=p->next) {
            fs_storenode(p,fd);
        }
    }
    fs_storenode(NULL,fd);	// end marker
}

void fs_storeedgelist(CFsEdge *e,FILE *fd) {
    while (e) {
        fs_storeedge(e,fd);
        e=e->nextChild;
    }
}

void fs_storeedges_rec(CFsNode *f,FILE *fd) {
    CFsEdge *e;
    fs_storeedgelist(f->data.ddata.children,fd);
    for (e=f->data.ddata.children ; e ; e=e->nextChild) {
        if (e->child->type==TYPE_DIRECTORY) {
            fs_storeedges_rec(e->child,fd);
        }
    }
}

void fs_storeedges(FILE *fd) {
    fs_storeedges_rec(CFsNode::s_root,fd);
    fs_storeedgelist(CFsEdge::s_trash,fd);
    fs_storeedgelist(CFsEdge::s_reserved,fd);
    fs_storeedge(NULL,fd);	// end marker
}

int fs_lostnode(CFsNode *p) {
    uint8_t artname[40];
    uint32_t i=0,l;
    do {
        if (i==0) {
            l = snprintf((char*)artname,40,"lost_node_%"PRIu32,p->id);
        } else {
            l = snprintf((char*)artname,40,"lost_node_%"PRIu32".%"PRIu32,p->id,i);
        }
        if (!CFsNode::s_root->nameisused(l,artname)) {
            CFsNode::link_edge(0,CFsNode::s_root,p,l,artname);
            return 1;
        }
        i++;
    } while (i);
    return -1;
}

int fs_checknodes(int ignoreflag) {
    uint32_t i;
    uint8_t nl;
    CFsNode *p;
    nl=1;
    for (i=0 ; i<NODEHASHSIZE ; i++) {
        for (p=CFsNode::s_nodehash[i] ; p ; p=p->next) {
            if (p->parents==NULL && p!=CFsNode::s_root) {
                if (nl) {
                    fputc('\n',stderr);
                    nl=0;
                }
                fprintf(stderr,"found orphaned inode: %"PRIu32"\n",p->id);
#ifndef METARESTORE
                syslog(LOG_ERR,"found orphaned inode: %"PRIu32,p->id);
#endif
                if (ignoreflag) {
                    if (fs_lostnode(p)<0) {
                        return -1;
                    }
                } else {
                    fprintf(stderr,"use mfsmetarestore (option -i) to attach this node to root dir\n");
                    return -1;
                }
            }
        }
    }
    return 1;
}

int fs_loadnodes(FILE *fd) {
    int s;
    fs_loadnode(NULL);
    do {
        s = fs_loadnode(fd);
        if (s<0) {
            return -1;
        }
    } while (s==0);
    return 0;
}

int fs_loadedges(FILE *fd,int ignoreflag) {
    int s;
    fs_loadedge(NULL,ignoreflag);	// init
    do {
        s = fs_loadedge(fd,ignoreflag);
        if (s<0) {
            return -1;
        }
    } while (s==0);
    return 0;
}

void fs_store(FILE *fd,uint8_t fver) {
    uint8_t hdr[16];
    uint8_t *ptr;
    off_t offbegin,offend;

    ptr = hdr;
    put32bit(&ptr, CFileIDMgr::getInstance()->get_max_id());
    put64bit(&ptr, CFileSysMgr::s_MetaVersion);
    put32bit(&ptr, CFileIDMgr::s_nextSID);
    if (fwrite(hdr,1,16,fd)!=(size_t)16) {
        syslog(LOG_NOTICE,"fwrite error");
        return;
    }
    if (fver>=0x16) {
        offbegin = ftello(fd);
        fseeko(fd,offbegin+16,SEEK_SET);
    } else {
        offbegin = 0;	// makes some old compilers happy
    }
    fs_storenodes(fd);
    if (fver>=0x16) {
        offend = ftello(fd);
        memcpy(hdr,"NODE 1.0",8);
        ptr = hdr+8;
        put64bit(&ptr,offend-offbegin-16);
        fseeko(fd,offbegin,SEEK_SET);
        if (fwrite(hdr,1,16,fd)!=(size_t)16) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        offbegin = offend;
        fseeko(fd,offbegin+16,SEEK_SET);
    }
    fs_storeedges(fd);
    if (fver>=0x16) {
        offend = ftello(fd);
        memcpy(hdr,"EDGE 1.0",8);
        ptr = hdr+8;
        put64bit(&ptr,offend-offbegin-16);
        fseeko(fd,offbegin,SEEK_SET);
        if (fwrite(hdr,1,16,fd)!=(size_t)16) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        offbegin = offend;
        fseeko(fd,offbegin+16,SEEK_SET);
    }

    CFileIDMgr::getInstance()->storefree(fd);
    if (fver>=0x16) {
        offend = ftello(fd);
        memcpy(hdr,"FREE 1.0",8);
        ptr = hdr+8;
        put64bit(&ptr,offend-offbegin-16);
        fseeko(fd,offbegin,SEEK_SET);
        if (fwrite(hdr,1,16,fd)!=(size_t)16) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        offbegin = offend;
        fseeko(fd,offbegin+16,SEEK_SET);

        CFsQuota::storequota(fd);

        offend = ftello(fd);
        memcpy(hdr,"QUOT 1.0",8);
        ptr = hdr+8;
        put64bit(&ptr,offend-offbegin-16);
        fseeko(fd,offbegin,SEEK_SET);
        if (fwrite(hdr,1,16,fd)!=(size_t)16) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        offbegin = offend;
        fseeko(fd,offbegin+16,SEEK_SET);

        CFsXAttrData::store_xattr(fd);

        offend = ftello(fd);
        memcpy(hdr,"XATR 1.0",8);
        ptr = hdr+8;
        put64bit(&ptr,offend-offbegin-16);
        fseeko(fd,offbegin,SEEK_SET);
        if (fwrite(hdr,1,16,fd)!=(size_t)16) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
        offbegin = offend;
        fseeko(fd,offbegin+16,SEEK_SET);
    }

    CChunkMgr::chunk_store(fd);
    if (fver>=0x16) {
        offend = ftello(fd);
        memcpy(hdr,"CHNK 1.0",8);
        ptr = hdr+8;
        put64bit(&ptr,offend-offbegin-16);
        fseeko(fd,offbegin,SEEK_SET);
        if (fwrite(hdr,1,16,fd)!=(size_t)16) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }

        fseeko(fd,offend,SEEK_SET);
        memcpy(hdr,"[MFS EOF MARKER]",16);
        if (fwrite(hdr,1,16,fd)!=(size_t)16) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
    }
}

uint64_t fs_loadversion(FILE *fd) {
    uint8_t hdr[12];
    if (fread(hdr,1,12,fd)!=12) {
        return 0;
    }
    const uint8_t *ptr = hdr+4;
    uint64_t fversion = get64bit(&ptr);
    return fversion;
}

int fs_load(FILE *fd,int ignoreflag,uint8_t fver) {
    uint8_t hdr[16];
    const uint8_t *ptr;
    off_t offbegin;
    uint64_t sleng;

    if (fread(hdr,1,16,fd)!=16) {
        fprintf(stderr,"error loading header\n");
        return -1;
    }
    ptr = hdr;
    CFileIDMgr::getInstance()->set_max_id( get32bit(&ptr) );
    CFileSysMgr::s_MetaVersion = get64bit(&ptr);
    CFileIDMgr::s_nextSID = get32bit(&ptr);
    CFileIDMgr::getInstance()->init_freebitmask();

    if (fver<0x16) {
        fprintf(stderr,"loading objects (files,directories,etc.) ... ");
        fflush(stderr);
        if (fs_loadnodes(fd)<0) {
#ifndef METARESTORE
            syslog(LOG_ERR,"error reading metadata (node)");
#endif
            return -1;
        }
        fprintf(stderr,"ok\n");
        fprintf(stderr,"loading names ... ");
        fflush(stderr);
        if (fs_loadedges(fd,ignoreflag)<0) {
#ifndef METARESTORE
            syslog(LOG_ERR,"error reading metadata (edge)");
#endif
            return -1;
        }
        fprintf(stderr,"ok\n");
        fprintf(stderr,"loading deletion timestamps ... ");
        fflush(stderr);
        if (CFileIDMgr::getInstance()->loadfree(fd)<0) {
#ifndef METARESTORE
            syslog(LOG_ERR,"error reading metadata (free)");
#endif
            return -1;
        }
        fprintf(stderr,"ok\n");
        fprintf(stderr,"loading chunks data ... ");
        fflush(stderr);
        if (CChunkMgr::chunk_load(fd)<0) {
            fprintf(stderr,"error\n");
#ifndef METARESTORE
            syslog(LOG_ERR,"error reading metadata (chunks)");
#endif
            fclose(fd);
            return -1;
        }
        fprintf(stderr,"ok\n");
    } else { // fver>=0x16
        while (1) {
            if (fread(hdr,1,16,fd)!=16) {
                fprintf(stderr,"error section header\n");
                return -1;
            }
            if (memcmp(hdr,"[MFS EOF MARKER]",16)==0) {
                break;
            }
            ptr = hdr+8;
            sleng = get64bit(&ptr);
            offbegin = ftello(fd);
            if (memcmp(hdr,"NODE 1.0",8)==0) {
                fprintf(stderr,"loading objects (files,directories,etc.) ... ");
                fflush(stderr);
                if (fs_loadnodes(fd)<0) {
#ifndef METARESTORE
                    syslog(LOG_ERR,"error reading metadata (node)");
#endif
                    return -1;
                }
            } else if (memcmp(hdr,"EDGE 1.0",8)==0) {
                fprintf(stderr,"loading names ... ");
                fflush(stderr);
                if (fs_loadedges(fd,ignoreflag)<0) {
#ifndef METARESTORE
                    syslog(LOG_ERR,"error reading metadata (edge)");
#endif
                    return -1;
                }
            } else if (memcmp(hdr,"FREE 1.0",8)==0) {
                fprintf(stderr,"loading deletion timestamps ... ");
                fflush(stderr);
                if (CFileIDMgr::getInstance()->loadfree(fd)<0) {
#ifndef METARESTORE
                    syslog(LOG_ERR,"error reading metadata (free)");
#endif
                    return -1;
                }
            } else if (memcmp(hdr,"QUOT 1.0",8)==0) {
                fprintf(stderr,"loading quota definitions ... ");
                fflush(stderr);
                if (CFsQuota::loadquota(fd,ignoreflag)<0) {
#ifndef METARESTORE
                    syslog(LOG_ERR,"error reading metadata (quota)");
#endif
                    return -1;
                }
            } else if (memcmp(hdr,"XATR 1.0",8)==0) {
                fprintf(stderr,"loading extra attributes (xattr) ... ");
                fflush(stderr);
                if (CFsXAttrNode::load_xattr(fd,ignoreflag)<0) {
#ifndef METARESTORE
                    syslog(LOG_ERR,"error reading metadata (xattr)");
#endif
                    return -1;
                }
            } else if (memcmp(hdr,"LOCK 1.0",8)==0) {
                fprintf(stderr,"ignoring locks\n");
                fseeko(fd,sleng,SEEK_CUR);
            } else if (memcmp(hdr,"CHNK 1.0",8)==0) {
                fprintf(stderr,"loading chunks data ... ");
                fflush(stderr);
                if (CChunkMgr::chunk_load(fd)<0) {
                    fprintf(stderr,"error\n");
#ifndef METARESTORE
                    syslog(LOG_ERR,"error reading metadata (chunks)");
#endif
                    fclose(fd);
                    return -1;
                }
            } else {
                hdr[8]=0;
                if (ignoreflag) {
                    fprintf(stderr,"unknown section found (leng:%"PRIu64",name:%s) - all data from this section will be lost !!!\n",sleng,hdr);
                    fseeko(fd,sleng,SEEK_CUR);
                } else {
                    fprintf(stderr,"error: unknown section found (leng:%"PRIu64",name:%s)\n",sleng,hdr);
                    return -1;
                }
            }
            if ((off_t)(offbegin+sleng)!=ftello(fd)) {
                fprintf(stderr,"not all section has been read - file corrupted\n");
                if (ignoreflag==0) {
                    return -1;
                }
            }
            fprintf(stderr,"ok\n");
        }
    }

    fprintf(stderr,"checking filesystem consistency ... ");
    fflush(stderr);
    CFsNode::s_root = CFsNode::id_to_node(MFS_ROOT_ID);
    if (CFsNode::s_root==NULL) {
        fprintf(stderr,"root node not found !!!\n");
#ifndef METARESTORE
        syslog(LOG_ERR,"error reading metadata (no root)");
#endif
        return -1;
    }

    if (fs_checknodes(ignoreflag)<0) {
        return -1;
    }
    fprintf(stderr,"ok\n");

    return 0;
}

#ifndef METARESTORE
void fs_new(void)
{
    CFileIDMgr::getInstance()->set_max_id( MFS_ROOT_ID );
    CFileSysMgr::s_MetaVersion = 0;
    CFileIDMgr::s_nextSID = 1;
    CFileIDMgr::getInstance()->init_freebitmask();

    CFsNode::s_root = (CFsNode*)malloc(sizeof(CFsNode));
    passert(CFsNode::s_root);
    CFsNode::s_root->id = MFS_ROOT_ID;
    CFsNode::s_root->type = TYPE_DIRECTORY;
    CFsNode::s_root->ctime = CFsNode::s_root->mtime = CFsNode::s_root->atime = CServerCore::get_time();
    CFsNode::s_root->goal = DEFAULT_GOAL;
    CFsNode::s_root->trashtime = DEFAULT_TRASHTIME;
    CFsNode::s_root->mode = 0777;
    CFsNode::s_root->uid = 0;
    CFsNode::s_root->gid = 0;

    STStatsRec *sr = (STStatsRec*)malloc(sizeof(STStatsRec));
    passert(sr);
    memset(sr,0,sizeof(STStatsRec));
    CFsNode::s_root->data.ddata.stats = sr;
    CFsNode::s_root->data.ddata.quota = NULL;
    CFsNode::s_root->data.ddata.children = NULL;
    CFsNode::s_root->data.ddata.elements = 0;
    CFsNode::s_root->data.ddata.nlink = 2;
    CFsNode::s_root->parents = NULL;

    uint32_t nodepos = NODEHASHPOS(CFsNode::s_root->id);
    CFsNode::s_root->next = CFsNode::s_nodehash[nodepos];
    CFsNode::s_nodehash[nodepos] = CFsNode::s_root;
    CFileIDMgr::getInstance()->used_inode(CFsNode::s_root->id);
    CChunkMgr::chunk_newfs();
    CFileSysMgr::s_nodes=1;
    CFileSysMgr::s_dirnodes=1;
    CFileSysMgr::s_filenodes=0;
}
#endif

int fs_emergency_storeall(const char *fname) {
    FILE *fd;
    fd = fopen(fname,"w");
    if (fd==NULL) {
        return -1;
    }
#if VERSHEX>=0x010700
    if (fwrite(MFSSIGNATURE "M 1.7",1,8,fd)!=(size_t)8) {
        syslog(LOG_NOTICE,"fwrite error");
    } else {
        fs_store(fd,0x17);
    }
#else
    if (fwrite(MFSSIGNATURE "M 1.5",1,8,fd)!=(size_t)8) {
        syslog(LOG_NOTICE,"fwrite error");
    } else {
        fs_store(fd,0x15);
    }
#endif
    if (ferror(fd)!=0) {
        fclose(fd);
        return -1;
    }
    fclose(fd);
    syslog(LOG_WARNING,"metadata were stored to emergency file: %s - please copy this file to your default location as 'metadata.mfs'",fname);

    return 0;
}

int fs_emergency_saves() {
#if defined(HAVE_PWD_H) && defined(HAVE_GETPWUID)
    struct passwd *p;
#endif
    if (fs_emergency_storeall("metadata.mfs.emergency")==0) {
        return 0;
    }
#if defined(HAVE_PWD_H) && defined(HAVE_GETPWUID)
    p = getpwuid(getuid());
    if (p) {
        char *fname;
        int l;
        l = strlen(p->pw_dir);
        fname = malloc(l+24);
        if (fname) {
            memcpy(fname,p->pw_dir,l);
            fname[l]='/';
            memcpy(fname+l+1,"metadata.mfs.emergency",22);
            fname[l+23]=0;
            if (fs_emergency_storeall(fname)==0) {
                free(fname);
                return 0;
            }
            free(fname);
        }
    }
#endif
    if (fs_emergency_storeall("/metadata.mfs.emergency")==0) {
        return 0;
    }
    if (fs_emergency_storeall("/tmp/metadata.mfs.emergency")==0) {
        return 0;
    }
    if (fs_emergency_storeall("/var/metadata.mfs.emergency")==0) {
        return 0;
    }
    if (fs_emergency_storeall("/usr/metadata.mfs.emergency")==0) {
        return 0;
    }
    if (fs_emergency_storeall("/usr/share/metadata.mfs.emergency")==0) {
        return 0;
    }
    if (fs_emergency_storeall("/usr/local/metadata.mfs.emergency")==0) {
        return 0;
    }
    if (fs_emergency_storeall("/usr/local/var/metadata.mfs.emergency")==0) {
        return 0;
    }
    if (fs_emergency_storeall("/usr/local/share/metadata.mfs.emergency")==0) {
        return 0;
    }
    return -1;
}

#ifndef METARESTORE
int fs_storeall(int bg) {
    FILE *fd;
    int i;
    struct stat sb;
    if (stat("metadata.mfs.back.tmp",&sb)==0) {
        syslog(LOG_ERR,"previous metadata save process hasn't finished yet - do not start another one");
        return -1;
    }
    changelog_rotate();
    if (bg) {
        i = fork();
    } else {
        i = -1;
    }

    // if fork returned -1 (fork error) store metadata in foreground !!!
    if (i<=0) {
        fd = fopen("metadata.mfs.back.tmp","w");
        if (fd==NULL) {
            syslog(LOG_ERR,"can't open metadata file");
            // try to save in alternative location - just in case
            fs_emergency_saves();
            if (i==0) {
                exit(0);
            }
            return 0;
        }
#if VERSHEX>=0x010700
        if (fwrite(MFSSIGNATURE "M 1.7",1,8,fd)!=(size_t)8) {
            syslog(LOG_NOTICE,"fwrite error");
        } else {
            fs_store(fd,0x17);
        }
#else
        if (fwrite(MFSSIGNATURE "M 1.5",1,8,fd)!=(size_t)8) {
            syslog(LOG_NOTICE,"fwrite error");
        } else {
            fs_store(fd,0x15);
        }
#endif
        if (ferror(fd)!=0) {
            syslog(LOG_ERR,"can't write metadata");
            fclose(fd);
            unlink("metadata.mfs.back.tmp");
            // try to save in alternative location - just in case
            fs_emergency_saves();
            if (i==0) {
                exit(0);
            }
            return 0;
        } else {
            fclose(fd);
            if (BackMetaCopies>0) {
                char metaname1[100],metaname2[100];
                int n;
                for (n=BackMetaCopies-1 ; n>0 ; n--) {
                    snprintf(metaname1,100,"metadata.mfs.back.%"PRIu32,n+1);
                    snprintf(metaname2,100,"metadata.mfs.back.%"PRIu32,n);
                    rename(metaname2,metaname1);
                }
                rename("metadata.mfs.back","metadata.mfs.back.1");
            }
            rename("metadata.mfs.back.tmp","metadata.mfs.back");
            unlink("metadata.mfs");
        }
        if (i==0) {
            exit(0);
        }
    }
    return 1;
}

void fs_dostoreall(void) {
    fs_storeall(1);	// ignore error
}

void fs_term(void) {
    for (;;) {
        if (fs_storeall(0)==1) {
            if (rename("metadata.mfs.back","metadata.mfs")<0) {
                mfs_errlog(LOG_WARNING,"can't rename metadata.mfs.back -> metadata.mfs");
            }
            chunk_term();
            return ;
        }
        syslog(LOG_ERR,"can't store metadata - try to make more space on your hdd or change privieleges - retrying after 10 seconds");
        sleep(10);
    }
}

#else
void fs_storeall(const char *fname) {
    FILE *fd;
    fd = fopen(fname,"w");
    if (fd==NULL) {
        printf("can't open metadata file\n");
        return;
    }
#if VERSHEX>=0x010700
    if (fwrite(MFSSIGNATURE "M 1.7",1,8,fd)!=(size_t)8) {
        syslog(LOG_NOTICE,"fwrite error");
    } else {
        fs_store(fd,0x17);
    }
#else
    if (fwrite(MFSSIGNATURE "M 1.5",1,8,fd)!=(size_t)8) {
        syslog(LOG_NOTICE,"fwrite error");
    } else {
        fs_store(fd,0x15);
    }
#endif
    if (ferror(fd)!=0) {
        printf("can't write metadata\n");
    }
    fclose(fd);
}

void fs_term(const char *fname) {
    fs_storeall(fname);
}
#endif

#ifndef METARESTORE
int fs_loadall(void) {
#else
int fs_loadall(const char *fname,int ignoreflag) {
#endif
    FILE *fd;
    uint8_t hdr[8];
#ifndef METARESTORE
    uint8_t bhdr[8];
    uint64_t backversion;
    int converted=0;
#endif

#ifdef METARESTORE
    fd = fopen(fname,"r");
#else
    backversion = 0;
    fd = fopen("metadata.mfs.back","r");
    if (fd!=NULL) {
        if (fread(bhdr,1,8,fd)==8) {
            if (memcmp(bhdr,MFSSIGNATURE "M 1.",7)==0 && (bhdr[7]=='5' || bhdr[7]=='7')) {
                backversion = fs_loadversion(fd);
            }
        }
        fclose(fd);
    }

    fd = fopen("metadata.mfs","r");
#endif
    if (fd==NULL) {
        fprintf(stderr,"can't open metadata file\n");
#ifndef METARESTORE
        {
#if defined(HAVE_GETCWD)
#ifndef PATH_MAX
#define PATH_MAX 10000
#endif
            char cwdbuf[PATH_MAX+1];
            int cwdlen;
            if (getcwd(cwdbuf,PATH_MAX)==NULL) {
                cwdbuf[0]=0;
            } else {
                cwdlen = strlen(cwdbuf);
                if (cwdlen>0 && cwdlen<PATH_MAX-1 && cwdbuf[cwdlen-1]!='/') {
                    cwdbuf[cwdlen]='/';
                    cwdbuf[cwdlen+1]=0;
                } else {
                    cwdbuf[0]=0;
                }
            }

#else
            char cwdbuf[1];
            cwdbuf[0]=0;
#endif
            if (cwdbuf[0]) {
                fprintf(stderr,"if this is new instalation then rename %smetadata.mfs.empty as %smetadata.mfs\n",cwdbuf,cwdbuf);
            } else {
                fprintf(stderr,"if this is new instalation then rename metadata.mfs.empty as metadata.mfs (in current working directory)\n");
            }
        }
        syslog(LOG_ERR,"can't open metadata file");
#endif
        return -1;
    }
    if (fread(hdr,1,8,fd)!=8) {
        fclose(fd);
        fprintf(stderr,"can't read metadata header\n");
#ifndef METARESTORE
        syslog(LOG_ERR,"can't read metadata header");
#endif
        return -1;
    }
#ifndef METARESTORE
    if (memcmp(hdr,"MFSM NEW",8)==0) {	// special case - create new file system
        fclose(fd);
        if (backversion>0) {
            fprintf(stderr,"backup file is newer than current file - please check it manually - propably you should run metarestore\n");
            syslog(LOG_ERR,"backup file is newer than current file - please check it manually - propably you should run metarestore");
            return -1;
        }
        if (rename("metadata.mfs","metadata.mfs.back")<0) {
            mfs_errlog(LOG_ERR,"can't rename metadata.mfs -> metadata.mfs.back");
            return -1;
        }
        fprintf(stderr,"create new empty filesystem");
        syslog(LOG_NOTICE,"create new empty filesystem");
        fs_new();
        unlink("metadata.mfs.back.tmp");
        fs_storeall(0);	// after creating new filesystem always create "back" file for using in metarestore
        return 0;
    }

#endif
    if (memcmp(hdr,MFSSIGNATURE "M 1.5",8)==0) {
#ifndef METARESTORE
        if (fs_load(fd,0,0x15)<0) {
#else
        if (fs_load(fd,ignoreflag,0x15)<0) {
#endif
#ifndef METARESTORE
            syslog(LOG_ERR,"error reading metadata (structure)");
#endif
            fclose(fd);
            return -1;
        }
    } else if (memcmp(hdr,MFSSIGNATURE "M 1.7",8)==0) {
#ifndef METARESTORE
        if (fs_load(fd,0,0x17)<0) {
#else
        if (fs_load(fd,ignoreflag,0x17)<0) {
#endif
#ifndef METARESTORE
            syslog(LOG_ERR,"error reading metadata (structure)");
#endif
            fclose(fd);
            return -1;
        }
    } else {
        fprintf(stderr,"wrong metadata header\n");
#ifndef METARESTORE
        syslog(LOG_ERR,"wrong metadata header");
#endif
        fclose(fd);
        return -1;
    }
    if (ferror(fd)!=0) {
        fprintf(stderr,"error reading metadata\n");
#ifndef METARESTORE
        syslog(LOG_ERR,"error reading metadata");
#endif
        fclose(fd);
        return -1;
    }
    fclose(fd);
#ifndef METARESTORE
    if (backversion>CFileSysMgr::s_MetaVersion) {
        mfs_syslog(LOG_ERR,"backup file is newer than current file - please check it manually - probably you should run metarestore");
        return -1;
    }
    if (converted==1) {
        if (rename("metadata.mfs","metadata.mfs.back.1.4")<0) {
            mfs_errlog(LOG_ERR,"can't rename metadata.mfs -> metadata.mfs.back.1.4");
            return -1;
        }
        fs_storeall(0);	// after conversion always create new version of "back" file for using in proper version of metarestore
    } else {
        if (rename("metadata.mfs","metadata.mfs.back")<0) {
            mfs_errlog(LOG_ERR,"can't rename metadata.mfs -> metadata.mfs.back");
            return -1;
        }
    }
#endif
    fprintf(stderr,"connecting files and chunks ... ");
    fflush(stderr);
    fs_add_files_to_chunks();
    fprintf(stderr,"ok\n");
#ifndef METARESTORE
    fprintf(stderr,"all inodes: %"PRIu32"\n", CFileSysMgr::s_nodes);
    fprintf(stderr,"directory inodes: %"PRIu32"\n",CFileSysMgr::s_dirnodes);
    fprintf(stderr,"file inodes: %"PRIu32"\n",CFileSysMgr::s_filenodes);
    fprintf(stderr,"chunks: %"PRIu32"\n", ChkMgr->chunk_count());
#endif
    unlink("metadata.mfs.back.tmp");
    return 0;
}

void fs_strinit(void) {
    uint32_t i;
    CFsNode::s_root = NULL;
    CFsEdge::s_trash = NULL;
    CFsEdge::s_reserved = NULL;
    CFileSysMgr::s_trashspace = 0;
    CFileSysMgr::s_reservedspace = 0;
    CFileSysMgr::s_trashnodes = 0;
    CFileSysMgr::s_reservednodes = 0;
#ifndef METARESTORE
    CFsQuota::s_quotaHead = NULL;
#endif
    CFsXAttrNode::xattr_init();
    for (i=0 ; i<NODEHASHSIZE ; i++) {
        CFsNode::s_nodehash[i]=NULL;
    }
    for (i=0 ; i<EDGEHASHSIZE ; i++) {
        CFsEdge::s_edgehash[i]=NULL;
    }
}

#ifndef METARESTORE

void fs_cs_disconnected(void) {
    test_start_time = CServerCore::get_time()+600;
}

void fs_reload(void) {
#if VERSHEX>=0x010700
    QuotaTimeLimit = cfg_getuint32("QUOTA_TIME_LIMIT",7*86400);
#endif
    BackMetaCopies = cfg_getuint32("BACK_META_KEEP_PREVIOUS",1);
    if (BackMetaCopies>99) {
        BackMetaCopies=99;
    }
}

int fs_init(void) {
    fprintf(stderr,"loading metadata ...\n");
    fs_strinit();
    chunk_strinit();
    test_start_time = CServerCore::get_time()+900;
    if (fs_loadall()<0) {
        return -1;
    }
    fprintf(stderr,"metadata file has been loaded\n");
#if VERSHEX>=0x010700
    CFsQuota::s_QuotaTimeLimit = cfg_getuint32("QUOTA_TIME_LIMIT",7*86400);
#else
    CFsQuota::s_QuotaTimeLimit = 7*86400;	// for tests
#endif
    BackMetaCopies = cfg_getuint32("BACK_META_KEEP_PREVIOUS",1);
    if (BackMetaCopies>99) {
        BackMetaCopies=99;
    }

    CServerCore::getInstance()->reload_register(fs_reload);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,1,0, fs_test_files);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,1,0, CFsQuota::check_all_quotas);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,3600,0, fs_dostoreall);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,300,0, fs_emptytrash);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,60,0, fs_emptyreserved);
    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,60,0, CFileIDMgr::freeinodes);
    CServerCore::getInstance()->destruct_register(fs_term);

    return 0;
}
#else
int fs_init(const char *fname,int ignoreflag) {
    fs_strinit();
    chunk_strinit();
    if (fs_loadall(fname,ignoreflag)<0) {
        return -1;
    }
    return 0;
}
#endif
