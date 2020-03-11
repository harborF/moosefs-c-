#ifndef _CSCOMM_H_
#define _CSCOMM_H_

int cs_readblock(int fd,uint64_t chunkid,uint32_t version,uint32_t offset,uint32_t size,uint8_t *buff);

#endif
