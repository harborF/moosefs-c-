#ifndef _CHUNK_CENTER_H__
#define _CHUNK_CENTER_H__
#define BGJOBS 1

#include <inttypes.h>
#include "DataPack.h"

#ifdef BGJOBS
typedef struct writestatus {
    uint32_t writeid;
    struct writestatus *next;
} writestatus;
#endif

class CFrontConn : public CConnEntry
{
public:
    uint8_t state;
    uint8_t fwdmode;
    CConnEntry stWEntry;

    uint8_t *fwdstartptr;		// used for forwarding inputpacket data
    uint32_t fwdbytesleft;		// used for forwarding inputpacket data
    uint8_t *fwdinitpacket;		// used only for write initialization

    uint64_t connstart;		// 'connect' start time in usec (for timeout and retry)
    uint32_t fwdip;			// 'connect' IP
    uint16_t fwdport;		// 'connect' port number
    uint8_t connretrycnt;		// 'connect' retry counter
    uint32_t activity;

#ifdef BGJOBS
    /* write */
    uint32_t wjobid;
    uint32_t wjobwriteid;
    writestatus *todolist;

    /* read */
    uint32_t rjobid;
    uint8_t todocnt;		// R (read finished + send finished)

    /* common for read and write but meaning is different !!! */
    void *rpacket;
    void *wpacket;
#endif

    uint8_t chunkisopen;
    uint64_t chunkid;		// R+W
    uint32_t version;		// R+W
    uint32_t offset;		// R
    uint32_t size;			// R

    CFrontConn *next;

public:
    void read_init(const uint8_t *data,uint32_t length);
    void write_init(const uint8_t *data,uint32_t length);
    void write_data(const uint8_t *data,uint32_t length);
    void write_status(const uint8_t *data,uint32_t length);

    void chunk_checksum_tab(const uint8_t *data,uint32_t length);
    void get_chunk_blocks(const uint8_t *data,uint32_t length);
    void chunk_checksum(const uint8_t *data,uint32_t length);
    void hdd_list_v1(const uint8_t *data,uint32_t length);
    void hdd_list_v2(const uint8_t *data,uint32_t length);

    void svr_chart(const uint8_t *data,uint32_t length);
    void svr_chart_data(const uint8_t *data,uint32_t length);
};

void csserv_stats(uint64_t *bin,uint64_t *bout,uint32_t *hlopr,uint32_t *hlopw,uint32_t *maxjobscnt);
uint32_t csserv_getlistenip();
uint16_t csserv_getlistenport();
int csserv_init(void);

#endif
