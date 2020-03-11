#include "config.h"

#include <fuse_lowlevel.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "DataPack.h"

typedef struct _dircache {
	struct fuse_ctx ctx;
	uint32_t parent;
	const uint8_t *dbuff;
	uint32_t dsize;
	uint32_t hashSize;
	const uint8_t **nameHashTab;
	const uint8_t **inodeHashTab;
	struct _dircache *next,**prev;
} STDirCache;

static STDirCache *s_pHead;
static pthread_mutex_t glock = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t dcache_hash(const uint8_t *name,uint8_t nleng) 
{
	uint32_t hash=5381;
	while (nleng>0) {
		hash = ((hash<<5)+hash)^(*name);
		name++;
		nleng--;
	}
	return hash;
}

uint32_t dcache_elemcount(const uint8_t *dbuff,uint32_t dsize)
{
	uint8_t enleng;
	uint32_t ret = 0;
    const uint8_t *ptr = dbuff,*eptr = dbuff+dsize;

	while (ptr<eptr) {
		enleng = *ptr;
		if (ptr+enleng+40<=eptr) {
			ret++;
		}
		ptr+=enleng+40;
	}
	return ret;
}

static inline void dcache_calchashsize(STDirCache *d)
{
	uint32_t cnt = dcache_elemcount(d->dbuff,d->dsize);
	d->hashSize = 1;
	cnt = (cnt*3)/2;
	while (cnt) {
		d->hashSize<<=1;
		cnt>>=1;
	}
}

void dcache_makenamehash(STDirCache *d) 
{
	const uint8_t *ptr,*eptr;
	uint8_t enleng;
	uint32_t hash,disp;
	uint32_t hashmask;

	if (d->hashSize==0) {
		dcache_calchashsize(d);
	}
	hashmask = d->hashSize-1;
	d->nameHashTab = (const uint8_t**)malloc(sizeof(uint8_t*)*d->hashSize);
	memset(d->nameHashTab,0,sizeof(uint8_t*)*d->hashSize);

	ptr = d->dbuff;
	eptr = d->dbuff+d->dsize;
	while (ptr<eptr) {
		enleng = *ptr;
		if (ptr+enleng+40<=eptr) {
			hash = dcache_hash(ptr+1,enleng);
			disp = ((hash*0x53B23891)&hashmask)|1;
			while (d->nameHashTab[hash&hashmask]) {
				hash+=disp;
			}
			d->nameHashTab[hash&hashmask]=ptr;
		}
		ptr+=enleng+40;
	}
}

void dcache_makeinodehash(STDirCache *d)
{
	uint8_t enleng;
	uint32_t hash,disp;

	if (d->hashSize==0) {
		dcache_calchashsize(d);
	}

	uint32_t hashmask = d->hashSize-1;
	d->inodeHashTab = (const uint8_t**)malloc(sizeof(uint8_t*)*d->hashSize);
	memset(d->inodeHashTab,0,sizeof(uint8_t*)*d->hashSize);

	const uint8_t *iptr;
	const uint8_t *ptr = d->dbuff;
	const uint8_t *eptr = d->dbuff+d->dsize;
	while (ptr<eptr) {
		enleng = *ptr;
		if (ptr+enleng+40<=eptr) {
			iptr = ptr+1+enleng;
			hash = get32bit(&iptr);
			disp = ((hash*0x53B23891)&hashmask)|1;
			hash *= 0xB28E457D;
			while (d->inodeHashTab[hash&hashmask]) {
				hash+=disp;
			}
			d->inodeHashTab[hash&hashmask]=ptr+1+enleng;
		}
		ptr+=enleng+40;
	}
}

void* dcache_new(const struct fuse_ctx *ctx,uint32_t parent,const uint8_t *dbuff,uint32_t dsize)
{
	STDirCache *d= (STDirCache*)malloc(sizeof(STDirCache));
	d->ctx.pid = ctx->pid;
	d->ctx.uid = ctx->uid;
	d->ctx.gid = ctx->gid;
	d->parent = parent;
	d->dbuff = dbuff;
	d->dsize = dsize;
	d->hashSize = 0;
	d->nameHashTab = NULL;
	d->inodeHashTab = NULL;
	pthread_mutex_lock(&glock);
	if (s_pHead) {
		s_pHead->prev = &(d->next);
	}
	d->next = s_pHead;
	d->prev = &s_pHead;
	s_pHead = d;
	pthread_mutex_unlock(&glock);

	return d;
}

void dcache_release(void *r)
{
	STDirCache *d = (STDirCache*)r;
	pthread_mutex_lock(&glock);
	if (d->next) {
		d->next->prev = d->prev;
	}
	*(d->prev) = d->next;
	pthread_mutex_unlock(&glock);
	if (d->nameHashTab) {
		free(d->nameHashTab);
	}
	if (d->inodeHashTab) {
		free(d->inodeHashTab);
	}
	free(d);
}

static inline uint8_t dcache_namehashsearch(STDirCache *d,uint8_t nleng,const uint8_t *name,uint32_t *inode,uint8_t attr[35]) 
{
	if (d->nameHashTab==NULL) {
		dcache_makenamehash(d);
	}

    const uint8_t *ptr;
	uint32_t hashmask = d->hashSize-1;
	uint32_t hash = dcache_hash(name,nleng);
	uint32_t disp = ((hash*0x53B23891)&hashmask)|1;
	while ((ptr=d->nameHashTab[hash&hashmask])) {
		if (*ptr==nleng && memcmp(ptr+1,name,nleng)==0) {
			ptr+=1+nleng;
			*inode = get32bit(&ptr);
			memcpy(attr,ptr,35);
			return 1;
		}
		hash+=disp;
	}
	return 0;
}

static inline uint8_t dcache_inodehashsearch(STDirCache *d,uint32_t inode,uint8_t attr[35])
{
	if (d->inodeHashTab==NULL) {
		dcache_makeinodehash(d);
	}

    const uint8_t *ptr;
	uint32_t hashmask = d->hashSize-1;
	uint32_t hash = inode*0xB28E457D;
	uint32_t disp = ((inode*0x53B23891)&hashmask)|1;
	while ((ptr=d->inodeHashTab[hash&hashmask])) {
		if (inode==get32bit(&ptr)) {
			memcpy(attr,ptr,35);
			return 1;
		}
		hash+=disp;
	}
	return 0;
}

uint8_t dcache_lookup(const struct fuse_ctx *ctx,uint32_t parent,uint8_t nleng,const uint8_t *name,uint32_t *inode,uint8_t attr[35])
{
	STDirCache *d;
	pthread_mutex_lock(&glock);
	for (d=s_pHead ; d ; d=d->next) {
		if (parent==d->parent && ctx->pid==d->ctx.pid && ctx->uid==d->ctx.uid && ctx->gid==d->ctx.gid) {
			if (dcache_namehashsearch(d,nleng,name,inode,attr)) {
				pthread_mutex_unlock(&glock);
				return 1;
			}
		}
	}
	pthread_mutex_unlock(&glock);

	return 0;
}

uint8_t dcache_getattr(const struct fuse_ctx *ctx,uint32_t inode,uint8_t attr[35])
{
	STDirCache *d;
	pthread_mutex_lock(&glock);
	for (d=s_pHead ; d ; d=d->next) {
		if (ctx->pid==d->ctx.pid && ctx->uid==d->ctx.uid && ctx->gid==d->ctx.gid) {
			if (dcache_inodehashsearch(d,inode,attr)) {
				pthread_mutex_unlock(&glock);
				return 1;
			}
		}
	}
	pthread_mutex_unlock(&glock);

	return 0;
}
