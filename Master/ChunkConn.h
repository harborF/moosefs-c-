#ifndef _CHUNK_CONN_H__
#define _CHUNK_CONN_H__
#include "DataPack.h"

class CChunkConn  : public CConnEntry
{
public:
    CChunkConn();
    ~CChunkConn();

public:
    char *servstrip;		// human readable version of servip
    uint32_t version;
    uint32_t servip;		// ip to coonnect to
    uint16_t servport;		// port to connect to
    uint16_t timeout;		// communication timeout

    uint64_t usedspace;		// used hdd space in bytes
    uint64_t totalspace;	// total hdd space in bytes
    uint32_t chunkscount;

    uint64_t todelUsedSpace;
    uint64_t todelTotalSpace;
    uint32_t todelChunksCount;

    uint32_t errorcounter;
    uint16_t rrepcounter;
    uint16_t wrepcounter;
    uint16_t delcounter;

    uint8_t incsdb;
    double carry;

    CChunkConn *next;

public:
    void svr_register(const uint8_t *data,uint32_t length);
    void got_replicatechunk_status(const uint8_t *data,uint32_t length);
    void got_setchunkversion_status(const uint8_t *data,uint32_t length);

    void handle_chunk_damaged(const uint8_t *data,uint32_t length);
    void chunks_lost(const uint8_t *data,uint32_t length);
    void chunks_new(const uint8_t *data,uint32_t length);
    void error_occurred(const uint8_t *data,uint32_t length);
    void svr_space(const uint8_t *data,uint32_t length);

    void got_duplicatechunk_status(const uint8_t *data,uint32_t length);
    void got_duptruncchunk_status(const uint8_t *data,uint32_t length);
    void got_chunkop_status(const uint8_t *data,uint32_t length);
    void got_truncatechunk_status(const uint8_t *data,uint32_t length);
    void got_deletechunk_status(const uint8_t *data,uint32_t length);
    void got_createchunk_status(const uint8_t *data,uint32_t length);
    void got_chunk_checksum(const uint8_t *data,uint32_t length);
};

#endif
