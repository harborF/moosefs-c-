#ifndef _CHUNK_FILE_H__
#define _CHUNK_FILE_H__

#include <inttypes.h>
#include <stdlib.h>
#include <string.h>

void file_cache_insert(uint32_t chunkid, uint32_t ver, uint8_t *buff, uint32_t size);
int file_cache_search(uint32_t chunkid, uint32_t ver, uint64_t offset, uint32_t size, uint8_t *buff);

void file_cache_init(void);
void file_cache_term(void);

#endif
