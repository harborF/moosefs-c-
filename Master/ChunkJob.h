#ifndef _CHUNKS_H_
#define _CHUNKS_H_
#include <stdio.h>
#include <inttypes.h>

#ifdef METARESTORE
int chunk_multi_modify(uint32_t ts,uint64_t *nchunkid,uint64_t ochunkid,uint8_t goal,uint8_t opflag);
int chunk_multi_truncate(uint32_t ts,uint64_t *nchunkid,uint64_t ochunkid,uint8_t goal);

#else
void chunk_store_info(uint8_t *buff);
int chunk_multi_modify(uint64_t *nchunkid,uint64_t ochunkid,uint8_t goal,uint8_t *opflag);
int chunk_multi_truncate(uint64_t *nchunkid,uint64_t ochunkid,uint32_t length,uint8_t goal);
int chunk_repair(uint8_t goal,uint64_t ochunkid,uint32_t *nversion);

/* ---- */
int get_version_locations(uint64_t chunkid,uint32_t cuip,uint32_t *version,uint8_t *count,uint8_t loc[256*6]);

#endif
/* ---- */
void chunk_term(void);
int chunk_strinit(void);

#endif
