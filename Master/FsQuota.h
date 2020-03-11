#ifndef _FILESYS_QUOTA_H__
#define _FILESYS_QUOTA_H__
#include "DataPack.h"

class CFsNode;
class CFsQuota
{
public:
    static CFsQuota *s_quotaHead;
#ifndef METARESTORE
    static uint32_t s_QuotaTimeLimit;
#endif

public:
    CFsQuota();
    ~CFsQuota();
public:
    uint8_t exceeded;	// hard quota exceeded or soft quota reached time limit
    uint8_t flags;
    uint32_t stimestamp;	// time when soft quota exceeded
    uint32_t sinodes,hinodes;
    uint64_t slength,hlength;
    uint64_t ssize,hsize;
    uint64_t srealsize,hrealsize;
    CFsNode *node;
    CFsQuota *next,**prev;

public:
#ifndef METARESTORE
    void check_quotanode(uint32_t ts);
    static void check_all_quotas(void);
#endif
    static void storequota(FILE *fd);
    static int loadquota(FILE *fd,int ignoreflag);
};

#endif
