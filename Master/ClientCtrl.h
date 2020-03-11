#ifndef _MATOCLSERV_H_
#define _MATOCLSERV_H_

#include <inttypes.h>

void matoclserv_stats(uint64_t stats[5]);
void matoclserv_chunk_status(uint64_t chunkid,uint8_t status);
int matoclserv_sessionsinit(void);
int matoclserv_networkinit(void);

#endif
