#include "FsQuota.h"
#include "FileSysMgr.h"

CFsQuota *CFsQuota::s_quotaHead = NULL;
#ifndef METARESTORE
uint32_t CFsQuota::s_QuotaTimeLimit = 0;
#endif

CFsQuota::CFsQuota():exceeded(0),
    flags(0),
    stimestamp(0),
    sinodes(0),
    hinodes(0),
    slength(0),hlength(0),
    ssize(0),hsize(0),
    srealsize(0),hrealsize(0),
    node(NULL),next(NULL),prev(NULL)
{

}

CFsQuota::~CFsQuota()
{
}

#ifndef METARESTORE

void CFsQuota::check_quotanode(uint32_t ts)
{
    STStatsRec *psr = node->data.ddata.stats;
    uint8_t hq=0,sq=0,chg=0,exceeded;

    if ((flags&QUOTA_FLAG_HINODES && psr->inodes>hinodes)
        ||(flags&QUOTA_FLAG_HLENGTH && psr->length>hlength)
        ||(flags&QUOTA_FLAG_HSIZE && psr->size>hsize)
        ||(flags&QUOTA_FLAG_HREALSIZE && psr->realsize>hrealsize))
    {
            hq=1;
    }

    if ((flags&QUOTA_FLAG_SINODES && psr->inodes>sinodes)
        || (flags&QUOTA_FLAG_SLENGTH && psr->length>slength)
        || (flags&QUOTA_FLAG_SSIZE && psr->size>ssize)
        || (flags&QUOTA_FLAG_SREALSIZE && psr->realsize>srealsize)) 
    {
            sq=1;
    }

    if (sq==0 && stimestamp>0) {
        stimestamp = 0;
        chg = 1;
    } else if (sq && stimestamp==0) {
        stimestamp = ts;
        chg = 1;
    }

    exceeded = (hq || (stimestamp && stimestamp+s_QuotaTimeLimit<ts))?1:0;
    if (exceeded != exceeded) {
        exceeded = exceeded;
        chg = 1;
    }
    if (chg) {
        changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|QUOTA(%"PRIu32",%"PRIu8",%"PRIu8",%"PRIu32",%"PRIu32",%"PRIu32",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64",%"PRIu64")",
            ts,node->id,exceeded,flags,stimestamp,sinodes,hinodes,slength,hlength,ssize,hsize,srealsize,hrealsize);
    }
}

void CFsQuota::check_all_quotas(void)
{
    CFsQuota *qn;
    uint32_t now = CServerCore::get_time();
    for (qn = s_quotaHead ; qn ; qn=qn->next)
    {
        qn->check_quotanode(now);
    }
}

#endif

// quota entry:
// inode:4 exceeded:1 flags:1 ts:4 sinodes:4 hinodes:4 slength:8 hlength:8 ssize:8 hsize:8 srealsize:8 hrealsize:8 = 66B
void CFsQuota::storequota(FILE *fd) 
{
    uint8_t wbuff[66*100],*ptr;
    CFsQuota *qn;
    uint32_t l=0;
    for (qn = s_quotaHead; qn ; qn=qn->next) {
        l++;
    }

    ptr = wbuff;
    put32bit(&ptr,l);
    if (fwrite(wbuff,1,4,fd)!=(size_t)4) {
        syslog(LOG_NOTICE,"fwrite error");
        return;
    }

    l=0;
    ptr=wbuff;
    for (qn = s_quotaHead ; qn ; qn=qn->next)
    {
        if (l==100) {
            if (fwrite(wbuff,1,66*100,fd)!=(size_t)(66*100)) {
                syslog(LOG_NOTICE,"fwrite error");
                return;
            }
            l=0;
            ptr=wbuff;
        }

        put32bit(&ptr,qn->node->id);
        put8bit(&ptr,qn->exceeded);
        put8bit(&ptr,qn->flags);
        put32bit(&ptr,qn->stimestamp);
        put32bit(&ptr,qn->sinodes);
        put32bit(&ptr,qn->hinodes);
        put64bit(&ptr,qn->slength);
        put64bit(&ptr,qn->hlength);
        put64bit(&ptr,qn->ssize);
        put64bit(&ptr,qn->hsize);
        put64bit(&ptr,qn->srealsize);
        put64bit(&ptr,qn->hrealsize);
        l++;
    }

    if (l>0) {
        if (fwrite(wbuff,1,66*l,fd)!=(66*l)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
    }
}

int CFsQuota::loadquota(FILE *fd,int ignoreflag)
{
    uint8_t rbuff[66*100];
    uint8_t nl=1;
    if (fread(rbuff,1,4,fd)!=4) {
        int err = errno;
        if (nl) {
            fputc('\n',stderr);
        }
        errno = err;
        mfs_errlog(LOG_ERR,"loading quota: read error");
        return -1;
    }

    CFsQuota *qn;
    CFsNode *fn;
    uint32_t l=0,t,id;
    const uint8_t *ptr=rbuff;
    t = get32bit(&ptr);
    s_quotaHead = NULL;
    while (t>0)
    {
        if (l==0)
        {
            if (t>100)
            {
                if (fread(rbuff,1,66*100,fd)!=66*100) 
                {
                    int err = errno;
                    if (nl) {
                        fputc('\n',stderr);
                        // nl=0;
                    }
                    errno = err;
                    mfs_errlog(LOG_ERR,"loading quota: read error");
                    return -1;
                }
                l=100;
            }
            else 
            {
                if (fread(rbuff,1,66*t,fd)!=66*t)
                {
                    int err = errno;
                    if (nl) {
                        fputc('\n',stderr);
                        // nl=0;
                    }
                    errno = err;
                    mfs_errlog(LOG_ERR,"loading free nodes: read error");
                    return -1;
                }
                l=t;
            }
            ptr = rbuff;
        }
        id = get32bit(&ptr);
        fn = CFsNode::id_to_node(id);
        if (fn==NULL || fn->type!=TYPE_DIRECTORY) {
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            fprintf(stderr,"quota defined for %s inode: %"PRIu32"\n",(fn==NULL)?"non existing":"not directory",id);
#ifndef METARESTORE
            syslog(LOG_ERR,"quota defined for %s inode: %"PRIu32,(fn==NULL)?"non existing":"not directory",id);
#endif
            if (ignoreflag) {
                ptr+=62;
            } else {
                fprintf(stderr,"use mfsmetarestore (option -i) to remove this quota definition");
                return -1;
            }
        } else {
            qn = fn->new_quotanode();
            qn->exceeded = get8bit(&ptr);
            qn->flags = get8bit(&ptr);
            qn->stimestamp = get32bit(&ptr);
            qn->sinodes = get32bit(&ptr);
            qn->hinodes = get32bit(&ptr);
            qn->slength = get64bit(&ptr);
            qn->hlength = get64bit(&ptr);
            qn->ssize = get64bit(&ptr);
            qn->hsize = get64bit(&ptr);
            qn->srealsize = get64bit(&ptr);
            qn->hrealsize = get64bit(&ptr);
        }
        l--;
        t--;
    }
    return 0;
}
