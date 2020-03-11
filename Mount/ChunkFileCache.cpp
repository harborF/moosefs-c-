#include "ChunkFileCache.h"
#include <time.h>
#include <pthread.h>

struct STNodeInfo
{
    uint32_t uiID;
    uint32_t uiVer;
    uint32_t uiRCout;
    uint32_t uiTime;
    uint32_t uiSize;
    uint8_t* pBuf;
    STNodeInfo *next;
};

static uint64_t s_uiTotal = 0;
static uint32_t s_uiMaxCount = 1000;
static STNodeInfo* s_pNodeHead, *s_pNodeTail;
static pthread_mutex_t s_cachelock = PTHREAD_MUTEX_INITIALIZER;

void file_cache_insert(uint32_t chunkid, uint32_t ver, uint8_t *pBuff, uint32_t size)
{
    if (size == 0 || pBuff == NULL){
        return;
    }

    pthread_mutex_lock(&s_cachelock);
    for(STNodeInfo* p = s_pNodeHead;p;p = p->next){
        if (chunkid == p->uiID)
        {
            pthread_mutex_unlock(&s_cachelock);
            return;
        }
    }
    
    STNodeInfo*pFind = s_pNodeHead;
    s_uiTotal -= pFind->uiSize;
    s_pNodeHead = pFind->next;
    s_pNodeTail->next = pFind;  
    s_pNodeTail = pFind;  
    s_pNodeTail->next = NULL;  

    uint32_t uiNow = time(NULL);
    pFind->uiID = chunkid;
    pFind->uiVer = ver;
    pFind->uiRCout = 1;
    pFind->uiTime = uiNow;
    pFind->uiSize = size;
    s_uiTotal += size;
    if (pFind->pBuf) {
        free(pFind->pBuf);
    } 
    pFind->pBuf = pBuff;  
    pthread_mutex_unlock(&s_cachelock);
}

int file_cache_search(uint32_t chunkid, uint32_t ver, uint64_t offset, uint32_t size, uint8_t *buff)
{
    pthread_mutex_lock(&s_cachelock);

    STNodeInfo*p = s_pNodeHead;
    STNodeInfo*pPrev = NULL, *pFind = NULL;
    while (p)
    {
        if (p->uiID == chunkid) {
            pFind = p;
            break;
        }        
        pPrev = p;
        p = p->next;
    }

    if (pFind == NULL || pFind->uiVer != ver
        || offset + size > pFind->uiSize)
    {
        pthread_mutex_unlock(&s_cachelock);
        return -1;
    }   

    uint32_t uiNow = time(NULL);
    if (pFind->uiTime + (60*24) < uiNow)
    {
        pFind->uiRCout = 1;
        pFind->uiTime = uiNow;
    }else{
        ++pFind->uiRCout;
    }
    
    if (pFind->next){
        if (pPrev){
            pPrev->next = pFind->next;
        }else{
            s_pNodeHead = pFind->next;
        }
        s_pNodeTail->next = pFind;
        s_pNodeTail = pFind;
        s_pNodeTail->next = NULL;
    }
    
    memcpy(buff, pFind->pBuf + offset, size);

    pthread_mutex_unlock(&s_cachelock);

    return 0;
}

void file_cache_init(void)
{
    s_pNodeHead = NULL;
    s_pNodeTail = NULL;
    for (int i = 0; i < s_uiMaxCount; ++i)
    {
        STNodeInfo* p = (STNodeInfo*)malloc(sizeof(STNodeInfo));
        p->pBuf = NULL;
        p->uiSize = 0;
        p->next = NULL;
        p->uiID = 0;
        p->uiVer = 0;
        p->uiRCout = 0;
        p->uiTime = 0;

        if(s_pNodeHead == NULL && s_pNodeTail == NULL){    
            s_pNodeHead = p;  
            s_pNodeTail = p;  
        }else{  
            s_pNodeTail->next = p;  
            s_pNodeTail = p;  
        }
    }    
}

void file_cache_term(void)
{
    STNodeInfo*p = s_pNodeHead, *pTmp;
    while (p)
    {
        pTmp = p;
        p = p->next;
        if (pTmp->pBuf)
        {
            free(pTmp->pBuf);
        }        
        free(pTmp);
    } 

    s_pNodeHead = NULL;
    s_pNodeTail = NULL;
}
