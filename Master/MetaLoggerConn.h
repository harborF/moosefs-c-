#ifndef _META_LOGGER_CONN_H__
#define _META_LOGGER_CONN_H__
#include "DataPack.h"
#define OLD_CHANGES_BLOCK_SIZE 5000

typedef struct old_changes_entry {
    uint64_t version;
    uint32_t length;
    uint8_t *data;
} old_changes_entry;

typedef struct old_changes_block {
    old_changes_entry old_blocks[OLD_CHANGES_BLOCK_SIZE];
    uint32_t entries;
    uint32_t mintimestamp;
    uint64_t minversion;
    struct old_changes_block *next;
} old_changes_block;

class CMetaLoggerConn  : public CConnEntry
{
public:
    static CMetaLoggerConn *s_pServHead;
    static uint16_t s_changelog_save;
    static old_changes_block *s_old_changes_head;
    static old_changes_block *s_old_changes_current;

    static uint32_t mloglist_size(void);
    static void serv_status(void);
    static void mloglist_data(uint8_t *ptr);

    static void old_changes_free_block(old_changes_block *oc);
    static void store_logstring(uint64_t version,uint8_t *logstr,uint32_t logstrsize);

public:
    void beforeclose();
    void send_old_changes(uint64_t version);
    void serv_register(const uint8_t *data,uint32_t length);
    void download_start(const uint8_t *data,uint32_t length);
    void download_data(const uint8_t *data,uint32_t length);
    void download_end(const uint8_t *data,uint32_t length);
public:
    uint32_t version;
    uint16_t timeout;

    char *servstrip;		// human readable version of servip
    uint32_t servip;

    int metafd,chain1fd,chain2fd;

    CMetaLoggerConn *next;
};

#endif
