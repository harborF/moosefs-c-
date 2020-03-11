#include "DataPack.h"

CConnEntry::CConnEntry()
{

}

CConnEntry::~CConnEntry()
{

}

void CConnEntry::init(int ns, uint32_t now)
{
    this->sock = ns;
    this->pdescpos = -1;
    this->lastread = now;
    this->lastwrite = now;
    this->inputpacket.next = NULL;
    this->inputpacket.bytesleft = 8;
    this->inputpacket.startptr = this->hdrbuff;
    this->inputpacket.packet = NULL;
    this->outputhead = NULL;
    this->outputtail = &(this->outputhead);
}

void CConnEntry::clear()
{
    if (inputpacket.packet)
    {
        free(inputpacket.packet);
    }

    packetStruct* paptr = NULL;
    packetStruct* pptr = outputhead;
    while (pptr) {
        if (pptr->packet) {
            free(pptr->packet);
        }
        paptr = pptr;
        pptr = pptr->next;
        free(paptr);
    }
}

void CConnEntry::attachPacket(void *packet)
{
    packetStruct *outpacket = (packetStruct*)packet;
    *(this->outputtail) = outpacket;
    this->outputtail = &(outpacket->next);
}

void* CConnEntry::newPacket(uint32_t type,uint32_t size)
{
    uint8_t *ptr;
    uint32_t psize;

    packetStruct *outpacket=(packetStruct*)malloc(sizeof(packetStruct));
    passert(outpacket);
    psize = size+8;

    outpacket->packet=(uint8_t*)malloc(psize);
    passert(outpacket->packet);

    outpacket->bytesleft = psize;
    ptr = outpacket->packet;

    put32bit(&ptr,type);
    put32bit(&ptr,size);

    outpacket->startptr = (uint8_t*)(outpacket->packet);
    outpacket->next = NULL;

    return outpacket;
}

uint8_t* CConnEntry::createPacket(uint32_t type,uint32_t size) 
{
    packetStruct *outpacket = (packetStruct*)newPacket(type, size);

    *(this->outputtail) = outpacket;
    this->outputtail = &(outpacket->next);

    return getPacketData(outpacket);
}

void CConnEntry::deletePacket(void *packet)
{
    packetStruct *outpacket = (packetStruct*)packet;
    free(outpacket->packet);
    free(outpacket);
}

char* CConnEntry::makestrip(uint32_t ip)
{
    uint8_t *ptr,pt[4];
    uint32_t l=0,i;
    ptr = pt;
    put32bit(&ptr,ip);
    for (i=0 ; i<4 ; i++) {
        if (pt[i]>=100) {
            l+=3;
        } else if (pt[i]>=10) {
            l+=2;
        } else {
            l+=1;
        }
    }
    l+=4;
    char *optr = (char *)malloc(l);
    passert(optr);
    snprintf(optr,l,"%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8,pt[0],pt[1],pt[2],pt[3]);
    optr[l-1]=0;
    return optr;
}

