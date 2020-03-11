#ifndef _READDATA_H_
#define _READDATA_H_

#include <inttypes.h>

void read_inode_ops(uint32_t inode);
void* read_data_new(uint32_t inode);
void read_data_end(void *rr);
int read_data(void *rr,uint64_t offset,uint32_t *size,uint8_t **buff);
void read_data_freebuff(void *rr);
void read_data_init(uint32_t retries);
void read_data_term(void);



void write_data_init(uint32_t cachesize,uint32_t retries);
void write_data_term(void);
void* write_data_new(uint32_t inode);
int write_data_end(void *vid);
int write_data_flush(void *vid);
uint64_t write_data_getmaxfleng(uint32_t inode);
int write_data_flush_inode(uint32_t inode);
int write_data(void *vid,uint64_t offset,uint32_t size,const uint8_t *buff);

#endif
