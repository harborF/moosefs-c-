#ifndef _MASTERCONN_H_
#define _MASTERCONN_H_
#include "DataPack.h"

class CMasterConn : public CConnEntry
{
public:
    static CMasterConn *s_Instance;
public:
    uint32_t bindip;
    uint32_t masterip;
    uint16_t masterport;
    uint8_t masteraddrvalid;

public:
    void handle_create(const uint8_t *data,uint32_t length);
    void handle_delete(const uint8_t *data,uint32_t length);
    void handle_setversion(const uint8_t *data,uint32_t length);
    void handle_duplicate(const uint8_t *data,uint32_t length);
    void handle_truncate(const uint8_t *data,uint32_t length);
    void handle_duptrunc(const uint8_t *data,uint32_t length);
    void handle_chunkop(const uint8_t *data,uint32_t length);
    void chunk_replicate(const uint8_t *data,uint32_t length);
    void chunk_checksum(const uint8_t *data,uint32_t length);
    void chunk_checksum_tab(const uint8_t *data,uint32_t length);
};

void masterconn_stats(uint64_t *bin,uint64_t *bout,uint32_t *maxjobscnt);
int masterconn_init(void);

#endif
