#include "FileIDMgr.h"
#include "changelog.h"
#include "FileSysMgr.h"

uint32_t CFileIDMgr::s_nextSID = 0;

CFileIDMgr::CFileIDMgr()
{

}

CFileIDMgr::~CFileIDMgr()
{

}

CFileIDMgr* CFileIDMgr::getInstance()
{
    static CFileIDMgr s_Instance;
    return &s_Instance;
}

void CFileIDMgr::free_id(uint32_t id,uint32_t ts)
{
    STFreeNode *n = freenode_malloc();
    n->id = id;
    n->ftime = ts;
    n->next = NULL;
    *m_freetail = n;
    m_freetail = &(n->next);
}

uint32_t CFileIDMgr::get_max_id()
{
    return this->m_maxNodeID;
}

void CFileIDMgr::set_max_id(uint32_t m)
{
    this->m_maxNodeID = m;
}

void CFileIDMgr::dumpfree()
{
    STFreeNode *n;
    for (n=getInstance()->m_freelist ; n ; n=n->next) {
        printf("I|i:%10"PRIu32"|f:%10"PRIu32"\n",n->id,n->ftime);
    }
}

uint32_t CFileIDMgr::get_next_id()
{
    while (m_searchpos<m_bitmasksize && m_freebitmask[m_searchpos]==0xFFFFFFFF)
    {
        m_searchpos++;
    }

    if (m_searchpos==m_bitmasksize) {	// no more freeinodes
        m_bitmasksize+=0x80;
        uint32_t *tmpfbm = m_freebitmask;
        m_freebitmask = (uint32_t*)realloc(m_freebitmask,m_bitmasksize*sizeof(uint32_t));
        if (m_freebitmask==NULL) {
            free(tmpfbm);
        }
        passert(m_freebitmask);
        memset(m_freebitmask+m_searchpos,0,0x80*sizeof(uint32_t));
    }

    uint32_t mask = m_freebitmask[m_searchpos];
    uint32_t i=0;
    while (mask&1) {
        i++;
        mask>>=1;
    }
    mask = 1<<i;

    m_freebitmask[m_searchpos] |= mask;
    i+=(m_searchpos<<5);
    if (i>m_maxNodeID) {
        m_maxNodeID=i;
    }

    return i;
}


#ifndef METARESTORE
void CFileIDMgr::freeinodes(void) {
#else
uint8_t CFileIDMgr::freeinodes(uint32_t ts,uint32_t fnodes) {
#endif
    uint32_t fi,now,pos,mask;
    STFreeNode *n,*an;
#ifndef METARESTORE
    now = CServerCore::get_time();
#else
    now = ts;
#endif
    CFileIDMgr* pThis = getInstance();

    fi = 0;
    n = pThis->m_freelist;
    while (n && n->ftime+86400<now) {
        fi++;
        pos = (n->id >> 5);
        mask = 1<<(n->id&0x1F);
        pThis->m_freebitmask[pos] &= ~mask;
        if (pos<pThis->m_searchpos) {
            pThis->m_searchpos = pos;
        }
        an = n->next;
        freenode_free(n);
        n = an;
    }

    if (n) {
        pThis->m_freelist = n;
    } else {
        pThis->m_freelist = NULL;
        pThis->m_freetail = &(pThis->m_freelist);
    }

#ifndef METARESTORE
    if (fi>0) {
        changelog(CFileSysMgr::s_MetaVersion++,"%" PRIu32 "|FREEINODES():%" PRIu32,(uint32_t)CServerCore::get_time(),fi);
    }
#else
    CFileSysMgr::s_MetaVersion++;
    if (fnodes!=fi) {
        return 1;
    }
    return 0;
#endif
}

void CFileIDMgr::init_freebitmask(void)
{
    m_bitmasksize = 0x100+(((m_maxNodeID)>>5)&0xFFFFFF80U);
    m_freebitmask = (uint32_t*)malloc(m_bitmasksize*sizeof(uint32_t));
    passert(m_freebitmask);
    memset(m_freebitmask, 0, m_bitmasksize*sizeof(uint32_t));
    m_freebitmask[0]=1;
    m_searchpos = 0;
}

void CFileIDMgr::used_inode (uint32_t id)
{
    uint32_t pos = id>>5;
    uint32_t mask = 1<<(id&0x1F);
    m_freebitmask[pos]|=mask;
}

#ifndef METARESTORE

uint32_t CFileIDMgr::newSessionID(void)
{
    changelog(CFileSysMgr::s_MetaVersion++,"%"PRIu32"|SESSION():%"PRIu32, (uint32_t)CServerCore::get_time(), s_nextSID);

    return s_nextSID++;
}

#else
uint8_t CFileIDMgr::fs_session(uint32_t sessionid)
{
    if (sessionid!=s_nextSID) {
        return ERROR_MISMATCH;
    }

    CFileSysMgr::s_MetaVersion++;
    s_nextSID++;

    return STATUS_OK;
}

#endif
//////////////////////////////////////////////////////////////////////////

void CFileIDMgr::storefree(FILE *fd)
{
    uint8_t wbuff[8*1024],*ptr;
    STFreeNode *n;
    uint32_t l;
    l=0;
    for (n=m_freelist ; n ; n=n->next) {
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
    for (n=m_freelist ; n ; n=n->next) {
        if (l==1024) {
            if (fwrite(wbuff,1,8*1024,fd)!=(size_t)(8*1024)) {
                syslog(LOG_NOTICE,"fwrite error");
                return;
            }
            l=0;
            ptr=wbuff;
        }
        put32bit(&ptr,n->id);
        put32bit(&ptr,n->ftime);
        l++;
    }
    if (l>0) {
        if (fwrite(wbuff,1,8*l,fd)!=(size_t)(8*l)) {
            syslog(LOG_NOTICE,"fwrite error");
            return;
        }
    }
}

int CFileIDMgr::loadfree(FILE *fd)
{
    uint8_t rbuff[8*1024];
    STFreeNode *n;
    uint32_t l,t;
    uint8_t nl=1;

    if (fread(rbuff,1,4,fd)!=4) {
        int err = errno;
        if (nl) {
            fputc('\n',stderr);
            // nl=0;
        }
        errno = err;
        mfs_errlog(LOG_ERR,"loading free nodes: read error");
        return -1;
    }

    const uint8_t *ptr=rbuff;
    t = get32bit(&ptr);
    m_freelist = NULL;
    m_freetail = &(m_freelist);
    l=0;
    while (t>0) {
        if (l==0) {
            if (t>1024) {
                if (fread(rbuff,1,8*1024,fd)!=8*1024) {
                    int err = errno;
                    if (nl) {
                        fputc('\n',stderr);
                    }
                    errno = err;
                    mfs_errlog(LOG_ERR,"loading free nodes: read error");
                    return -1;
                }
                l=1024;
            } else {
                if (fread(rbuff,1,8*t,fd)!=8*t) {
                    int err = errno;
                    if (nl) {
                        fputc('\n',stderr);
                    }
                    errno = err;
                    mfs_errlog(LOG_ERR,"loading free nodes: read error");
                    return -1;
                }
                l=t;
            }
            ptr = rbuff;
        }
        n = freenode_malloc();
        n->id = get32bit(&ptr);
        n->ftime = get32bit(&ptr);
        n->next = NULL;
        *m_freetail = n;
        m_freetail = &(n->next);
        used_inode(n->id);
        l--;
        t--;
    }

    return 0;
}

