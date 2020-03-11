#ifndef _DATAPACK_H_
#define _DATAPACK_H_

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "massert.h"
#include "slogger.h"
#include "StatusDef.h"
#include "CmdDefine.h"

#define SAFE_DELETE(p) { if(p) { delete (p); (p)=NULL; } }
#define SAFE_DELETE_ARRAY(p) { if(p) { delete[] (p); (p)=NULL; } }

/* MFS data pack */
static inline void put64bit(uint8_t **ptr,uint64_t val) {
	(*ptr)[0]=((val)>>56)&0xFF;
	(*ptr)[1]=((val)>>48)&0xFF;
	(*ptr)[2]=((val)>>40)&0xFF;
	(*ptr)[3]=((val)>>32)&0xFF;
	(*ptr)[4]=((val)>>24)&0xFF;
	(*ptr)[5]=((val)>>16)&0xFF;
	(*ptr)[6]=((val)>>8)&0xFF;
	(*ptr)[7]=(val)&0xFF;
	(*ptr)+=8;
}

static inline void put32bit(uint8_t **ptr,uint32_t val) {
	(*ptr)[0]=((val)>>24)&0xFF;
	(*ptr)[1]=((val)>>16)&0xFF;
	(*ptr)[2]=((val)>>8)&0xFF;
	(*ptr)[3]=(val)&0xFF;
	(*ptr)+=4;
}

static inline void put16bit(uint8_t **ptr,uint16_t val) {
	(*ptr)[0]=((val)>>8)&0xFF;
	(*ptr)[1]=(val)&0xFF;
	(*ptr)+=2;
}

static inline void put8bit(uint8_t **ptr,uint8_t val) {
	(*ptr)[0]=(val)&0xFF;
	(*ptr)++;
}

static inline uint64_t get64bit(const uint8_t **ptr) {
	uint64_t t64;
	t64=((*ptr)[3]+256U*((*ptr)[2]+256U*((*ptr)[1]+256U*(*ptr)[0])));
	t64<<=32;
	t64|=(uint32_t)(((*ptr)[7]+256U*((*ptr)[6]+256U*((*ptr)[5]+256U*(*ptr)[4]))));
	(*ptr)+=8;
	return t64;
}

static inline uint32_t get32bit(const uint8_t **ptr) {
	uint32_t t32;
	t32=((*ptr)[3]+256U*((*ptr)[2]+256U*((*ptr)[1]+256U*(*ptr)[0])));
	(*ptr)+=4;
	return t32;
}

static inline uint16_t get16bit(const uint8_t **ptr) {
	uint32_t t16;
	t16=(*ptr)[1]+256U*(*ptr)[0];
	(*ptr)+=2;
	return t16;
}

static inline uint8_t get8bit(const uint8_t **ptr) {
	uint32_t t8;
	t8=(*ptr)[0];
	(*ptr)++;
	return t8;
}

typedef struct packetStruct {
    struct packetStruct *next;
    uint8_t *startptr;
    uint32_t bytesleft;
    uint8_t *packet;
} packetStruct;

typedef enum {IDLE, FREE, CONNECTING, HEADER, DATA, KILL}E_ModeType;

class CConnEntry
{
public:
    CConnEntry();
    virtual ~CConnEntry();
public:
    int sock;
    E_ModeType mode;
    int32_t pdescpos;
    uint32_t lastread;
    uint32_t lastwrite;
    uint8_t hdrbuff[8];
    packetStruct inputpacket;
    packetStruct *outputhead,**outputtail;
public:
    void clear();
    void init(int ns, uint32_t now);

    void attachPacket(void *packet);

    static void* newPacket(uint32_t type,uint32_t size);
    uint8_t* createPacket(uint32_t type,uint32_t size);

    static void deletePacket(void *packet);
    static inline uint8_t* getPacketData(void *packet);

    static char* makestrip(uint32_t ip);
};

inline uint8_t* CConnEntry::getPacketData(void *packet) {
    packetStruct *outpacket = (packetStruct*)packet;
    return outpacket->packet+8;
}

#endif
