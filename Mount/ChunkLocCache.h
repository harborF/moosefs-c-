#ifndef _CHUNKLOC_CACHE_H_
#define _CHUNKLOC_CACHE_H_

#include <inttypes.h>

void chunkloc_cache_insert(uint32_t inode,uint32_t pos,uint64_t chunkid,uint32_t chunkversion,uint8_t csdatasize,const uint8_t *csdata);
int chunkloc_cache_search(uint32_t inode,uint32_t pos,uint64_t *chunkid,uint32_t *chunkversion,uint8_t *csdatasize,const uint8_t **csdata);
void chunkloc_cache_init(void);
void chunkloc_cache_term(void);

#endif
