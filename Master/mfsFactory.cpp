#include "mfsFactory.h"

template<typename T, int TMax>
TEntryBucket<T,TMax>::TEntryBucket():tbhead(NULL),tfreehead(NULL)
{
}

template<typename T, int TMax>
TEntryBucket<T,TMax>::~TEntryBucket()
{
    this->freeAll();
}

template<typename T, int TMax>
T* TEntryBucket<T,TMax>::newT(){
    T *ret;
    if (tfreehead) {
        ret = tfreehead;
        tfreehead = ret->next;
        return ret;
    }

    if (tbhead==NULL || tbhead->firstfree==TMax) {
        T_bucket *crb = (T_bucket*)malloc(sizeof(T_bucket));
        passert(crb);
        crb->next = tbhead;
        crb->firstfree = 0;
        tbhead = crb;
    }
    ret = (tbhead->bucket)+(tbhead->firstfree);
    tbhead->firstfree++;
    return ret;
}

template<typename T, int TMax>
void TEntryBucket<T,TMax>::freeT(T* p){
    p->next = tfreehead;
    tfreehead = p;
}

template<typename T, int TMax>
void TEntryBucket<T,TMax>::freeAll(){
    T_bucket* tbn = NULL;
    for (T_bucket* tb = tbhead ; tb ; tb = tbn) {
        tbn = tb->next;
        free(tb);
    }
}

//////////////////////////////////////////////////////////////////////////

#ifdef USE_CUIDREC_BUCKETS

static TEntryBucket<STSIDRec, 1000> s_scrbucket;

STSIDRec* sessionidrec_malloc() {
    return s_scrbucket.newT();
}

void sessionidrec_free(STSIDRec *p) {
    s_scrbucket.freeT(p);
}
#else /* USE_CUIDREC_BUCKETS */

STSIDRec* sessionidrec_malloc() {
    STSIDRec *sidrec = (STSIDRec*)malloc(sizeof(STSIDRec));
    passert(sidrec);
    return sidrec;
}

void sessionidrec_free(STSIDRec* p) {
    free(p);
}

#endif /* USE_CUIDREC_BUCKETS */

#ifdef USE_FREENODE_BUCKETS

static TEntryBucket<STFreeNode, 5000> s_fnbucket;

STFreeNode* freenode_malloc() {
    return s_fnbucket.newT();
}

void freenode_free(STFreeNode *p) {
   s_fnbucket.freeT(p);
}
#else /* USE_FREENODE_BUCKETS */

STFreeNode* freenode_malloc() {
    STFreeNode *fn = (STFreeNode*)malloc(sizeof(STFreeNode));
    passert(fn);
    return fn;
}

void freenode_free(STFreeNode* p) {
    free(p);
}

#endif /* USE_FREENODE_BUCKETS */

#ifndef METARESTORE

#ifdef USE_SLIST_BUCKETS

static TEntryBucket<slist, 5000> s_slbucket;

slist* slist_malloc() {
    return s_slbucket.newT();
}

void slist_free(slist *p) {
    s_slbucket.freeT(p);
}

#else
slist* slist_malloc() {
    slist *sl = (slist*)malloc(sizeof(slist));
    passert(sl);
    return sl;
}

void slist_free(slist* p) {
    free(p);
}

#endif /* USE_SLIST_BUCKET */

#endif

#ifdef USE_CHUNK_BUCKETS

static TEntryBucket<CChunkObj, 20000> s_chbucket;

CChunkObj* chunk_malloc() {
    return s_chbucket.newT();
}

void chunk_free(CChunkObj *p) {
    s_chbucket.freeT(p);
}

#else
CChunkObj* chunk_malloc() {
    CChunkObj *cu = (CChunkObj*)malloc(sizeof(CChunkObj));
    passert(cu);
    return cu;
}

void chunk_free(CChunkObj* p) {
    free(p);
}

#endif /* USE_CHUNK_BUCKETS */

