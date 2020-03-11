#ifndef _FILE_ID_MGR_H__
#define _FILE_ID_MGR_H__
#include "DataPack.h"
#include "mfsFactory.h"

class CFileIDMgr
{
public:
    static uint32_t s_nextSID;
protected:
    CFileIDMgr();
public:
    ~CFileIDMgr();
    static CFileIDMgr* getInstance();

public:
    uint32_t get_next_id();
    uint32_t get_max_id();
    void set_max_id(uint32_t m);
    void free_id(uint32_t id,uint32_t ts);
    void used_inode (uint32_t id);
    void init_freebitmask(void);

#ifndef METARESTORE
    static void freeinodes(void);
    static uint32_t newSessionID(void);
#else
    static uint8_t freeinodes(uint32_t ts,uint32_t fnodes);
    static uint8_t fs_session(uint32_t sessionid);
#endif

    static void dumpfree();
    void storefree(FILE *fd);
    int loadfree(FILE *fd);
private:
    uint32_t* m_freebitmask;
    uint32_t m_bitmasksize;
    uint32_t m_searchpos;
    uint32_t m_maxNodeID;
    STFreeNode *m_freelist,**m_freetail;
};

#endif
