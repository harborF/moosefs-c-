#include "ChunkConn.h"
#include "ChunkCtrl.h"
#include "sockets.h"

CChunkConn::CChunkConn()
{
}

CChunkConn::~CChunkConn()
{
}

void CChunkConn::svr_register(const uint8_t *data,uint32_t length)
{
    uint64_t chunkid;
    uint32_t chunkversion;
    uint32_t i,chunkcount;
    uint8_t rversion;
    double us,ts;

    if (this->totalspace>0) {
        syslog(LOG_WARNING,"got register message from registered chunk-server !!!");
        this->mode=KILL;
        return;
    }

    if ((length&1)==0) {
        if (length<22 || ((length-22)%12)!=0) {
            syslog(LOG_NOTICE,"CSTOMA_REGISTER (old ver.) - wrong size (%"PRIu32"/22+N*12)",length);
            this->mode=KILL;
            return;
        }
        passert(data);
        this->servip = get32bit(&data);
        this->servport = get16bit(&data);
        this->usedspace = get64bit(&data);
        this->totalspace = get64bit(&data);
        length-=22;
        rversion=0;
    } else {
        passert(data);
        rversion = get8bit(&data);
        if (rversion<=4) {
            syslog(LOG_NOTICE,"register packet version: %u",rversion);
        }
        if (rversion==1) {
            if (length<39 || ((length-39)%12)!=0) {
                syslog(LOG_NOTICE,"CSTOMA_REGISTER (ver 1) - wrong size (%"PRIu32"/39+N*12)",length);
                this->mode=KILL;
                return;
            }
            this->servip = get32bit(&data);
            this->servport = get16bit(&data);
            this->usedspace = get64bit(&data);
            this->totalspace = get64bit(&data);
            this->todelUsedSpace = get64bit(&data);
            this->todelTotalSpace = get64bit(&data);
            length-=39;
        } else if (rversion==2) {
            if (length<47 || ((length-47)%12)!=0) {
                syslog(LOG_NOTICE,"CSTOMA_REGISTER (ver 2) - wrong size (%"PRIu32"/47+N*12)",length);
                this->mode=KILL;
                return;
            }
            this->servip = get32bit(&data);
            this->servport = get16bit(&data);
            this->usedspace = get64bit(&data);
            this->totalspace = get64bit(&data);
            this->chunkscount = get32bit(&data);
            this->todelUsedSpace = get64bit(&data);
            this->todelTotalSpace = get64bit(&data);
            this->todelChunksCount = get32bit(&data);
            length-=47;
        } else if (rversion==3) {
            if (length<49 || ((length-49)%12)!=0) {
                syslog(LOG_NOTICE,"CSTOMA_REGISTER (ver 3) - wrong size (%"PRIu32"/49+N*12)",length);
                this->mode=KILL;
                return;
            }
            this->servip = get32bit(&data);
            this->servport = get16bit(&data);
            this->timeout = get16bit(&data);
            this->usedspace = get64bit(&data);
            this->totalspace = get64bit(&data);
            this->chunkscount = get32bit(&data);
            this->todelUsedSpace = get64bit(&data);
            this->todelTotalSpace = get64bit(&data);
            this->todelChunksCount = get32bit(&data);
            length-=49;
        } else if (rversion==4) {
            if (length<53 || ((length-53)%12)!=0) {
                syslog(LOG_NOTICE,"CSTOMA_REGISTER (ver 4) - wrong size (%"PRIu32"/53+N*12)",length);
                this->mode=KILL;
                return;
            }
            this->version = get32bit(&data);
            this->servip = get32bit(&data);
            this->servport = get16bit(&data);
            this->timeout = get16bit(&data);
            this->usedspace = get64bit(&data);
            this->totalspace = get64bit(&data);
            this->chunkscount = get32bit(&data);
            this->todelUsedSpace = get64bit(&data);
            this->todelTotalSpace = get64bit(&data);
            this->todelChunksCount = get32bit(&data);
            length-=53;
        } else if (rversion==50) {
            if (length!=13) {
                syslog(LOG_NOTICE,"CSTOMA_REGISTER (ver 5:BEGIN) - wrong size (%"PRIu32"/13)",length);
                this->mode=KILL;
                return;
            }
            this->version = get32bit(&data);
            this->servip = get32bit(&data);
            this->servport = get16bit(&data);
            this->timeout = get16bit(&data);
            if (this->timeout<10) {
                syslog(LOG_NOTICE,"CSTOMA_REGISTER communication timeout too small (%"PRIu16" seconds - should be at least 10 seconds)",this->timeout);
                this->mode=KILL;
                return;
            }
            if (this->servip==0) {
                tcpGetPeer(this->sock,&(this->servip),NULL);
            }
            if (this->servstrip) {
                free(this->servstrip);
            }
            this->servstrip = CConnEntry::makestrip(this->servip);
            if (((this->servip)&0xFF000000) == 0x7F000000) {
                syslog(LOG_NOTICE,"chunkserver connected using localhost (IP: %s) - you cannot use localhost for communication between chunkserver and master", this->servstrip);
                this->mode=KILL;
                return;
            }

            if (CChunkSvrMgr::getInstance()->new_connection(this->servip,this->servport,this)<0) {
                syslog(LOG_WARNING,"chunk-server already connected !!!");
                this->mode=KILL;
                return;
            }
            this->incsdb = 1;
            syslog(LOG_NOTICE,"chunkserver register begin (packet version: 5) - ip: %s, port: %"PRIu16,this->servstrip,this->servport);
            
            return;
        } else if (rversion==51) {
            if (((length-1)%12)!=0) {
                syslog(LOG_NOTICE,"CSTOMA_REGISTER (ver 5:CHUNKS) - wrong size (%"PRIu32"/1+N*12)",length);
                this->mode=KILL;
                return;
            }

            chunkcount = (length-1)/12;
            for (i=0 ; i<chunkcount ; i++) {
                chunkid = get64bit(&data);
                chunkversion = get32bit(&data);
                CChunkMgr::getInstance()->chunk_server_has_chunk(this, chunkid, chunkversion);
            }

            return;
        } else if (rversion==52) {
            if (length!=41) {
                syslog(LOG_NOTICE,"CSTOMA_REGISTER (ver 5:END) - wrong size (%"PRIu32"/41)",length);
                this->mode=KILL;
                return;
            }

            this->usedspace = get64bit(&data);
            this->totalspace = get64bit(&data);
            this->chunkscount = get32bit(&data);
            this->todelUsedSpace = get64bit(&data);
            this->todelTotalSpace = get64bit(&data);
            this->todelChunksCount = get32bit(&data);
            us = (double)(this->usedspace)/(double)(1024*1024*1024);
            ts = (double)(this->totalspace)/(double)(1024*1024*1024);
            syslog(LOG_NOTICE,"chunkserver register end (packet version: 5) - ip: %s, port: %"PRIu16", usedspace: %"PRIu64" (%.2lf GiB), totalspace: %"PRIu64" (%.2lf GiB)",this->servstrip,this->servport,this->usedspace,us,this->totalspace,ts);
            
            return;
        } else {
            syslog(LOG_NOTICE,"CSTOMA_REGISTER - wrong version (%"PRIu8"/1..4)",rversion);
            this->mode=KILL;
            return;
        }
    }
    if (rversion<=4) {
        if (this->timeout<10) {
            syslog(LOG_NOTICE,"CSTOMA_REGISTER communication timeout too small (%"PRIu16" seconds - should be at least 10 seconds)",this->timeout);
            if (this->timeout<3) {
                this->timeout=3;
            }
            return;
        }

        if (this->servip==0) {
            tcpGetPeer(this->sock,&(this->servip),NULL);
        }
        if (this->servstrip) {
            free(this->servstrip);
        }

        this->servstrip = CConnEntry::makestrip(this->servip);
        if (((this->servip)&0xFF000000) == 0x7F000000) {
            syslog(LOG_NOTICE,"chunkserver connected using localhost (IP: %s) - you cannot use localhost for communication between chunkserver and master", this->servstrip);
            this->mode=KILL;
            return;
        }

        us = (double)(this->usedspace)/(double)(1024*1024*1024);
        ts = (double)(this->totalspace)/(double)(1024*1024*1024);
        syslog(LOG_NOTICE,"chunkserver register - ip: %s, port: %"PRIu16", usedspace: %"PRIu64" (%.2lf GiB), totalspace: %"PRIu64" (%.2lf GiB)",this->servstrip,this->servport,this->usedspace,us,this->totalspace,ts);
       
        if (CChunkSvrMgr::getInstance()->new_connection(this->servip,this->servport,this)<0) {
            syslog(LOG_WARNING,"chunk-server already connected !!!");
            this->mode=KILL;
            return;
        }

        this->incsdb = 1;
        chunkcount = length/(8+4);

        for (i=0 ; i<chunkcount ; i++) {
            chunkid = get64bit(&data);
            chunkversion = get32bit(&data);
            CChunkMgr::getInstance()->chunk_server_has_chunk(this,chunkid,chunkversion);
        }
    }
}

void CChunkConn::got_replicatechunk_status(const uint8_t *data,uint32_t length)
{
    if (length!=8+4+1) {
        syslog(LOG_NOTICE,"CSTOMA_REPLICATE - wrong size (%"PRIu32"/13)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint32_t version = get32bit(&data);
    CChunkSvrMgr::getInstance()->replication_end(chunkid,version,this);
    uint8_t status = get8bit(&data);
    CChunkMgr::getInstance()->got_replicate_status(this,chunkid,version,status);

    if (status!=0) {
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" replication status: %s",this->servstrip,this->servport,chunkid,mfsstrerr(status));
    }
}

void CChunkConn::got_setchunkversion_status(const uint8_t *data,uint32_t length)
{
    if (length!=8+1) {
        syslog(LOG_NOTICE,"CSTOMA_SET_VERSION - wrong size (%"PRIu32"/9)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint8_t status = get8bit(&data);
    chunk_got_setversion_status(this,chunkid,status);
    if (status!=0) {
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" set version status: %s",this->servstrip,this->servport,chunkid,mfsstrerr(status));
    }
}

void CChunkConn::got_duplicatechunk_status(const uint8_t *data,uint32_t length)
{
    if (length!=8+1) {
        syslog(LOG_NOTICE,"CSTOMA_DUPLICATE - wrong size (%"PRIu32"/9)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint8_t status = get8bit(&data);
    chunk_got_duplicate_status(this,chunkid,status);
    if (status!=0) {
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" duplication status: %s",this->servstrip,this->servport,chunkid,mfsstrerr(status));
    }
}

void CChunkConn::got_duptruncchunk_status(const uint8_t *data,uint32_t length) 
{
    if (length!=8+1) {
        syslog(LOG_NOTICE,"CSTOMA_DUPTRUNC - wrong size (%"PRIu32"/9)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint8_t status = get8bit(&data);
    chunk_got_duptrunc_status(this,chunkid,status);
    if (status!=0) {
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" duplication with truncate status: %s",this->servstrip,this->servport,chunkid,mfsstrerr(status));
    }
}

void CChunkConn::got_chunkop_status(const uint8_t *data,uint32_t length) 
{
    if (length!=8+4+4+8+4+4+1) {
        syslog(LOG_NOTICE,"CSTOMA_CHUNKOP - wrong size (%"PRIu32"/33)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint32_t version = get32bit(&data);
    uint32_t newversion = get32bit(&data);
    uint64_t copychunkid = get64bit(&data);
    uint32_t copyversion = get32bit(&data);
    uint32_t leng = get32bit(&data);
    uint8_t status = get8bit(&data);

    if (newversion!=version) {
        CChunkMgr::getInstance()->got_chunkop_status(this,chunkid,status);
    }

    if (copychunkid>0) {
        CChunkMgr::getInstance()->got_chunkop_status(this,copychunkid,status);
    }

    if (status!=0) {
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunkop(%016"PRIX64",%08"PRIX32",%08"PRIX32",%016"PRIX64",%08"PRIX32",%"PRIu32") status: %s",this->servstrip,this->servport,chunkid,version,newversion,copychunkid,copyversion,leng,mfsstrerr(status));
    }
}

void CChunkConn::handle_chunk_damaged(const uint8_t *data,uint32_t length)
{
    if (length%8!=0) {
        syslog(LOG_NOTICE,"CSTOMA_CHUNK_DAMAGED - wrong size (%"PRIu32"/N*8)",length);
        this->mode=KILL;
        return;
    }
    if (length>0) {
        passert(data);
    }  

    for (uint32_t i=0 ; i<length/8 ; i++) {
        uint64_t chunkid = get64bit(&data);
        CChunkMgr::getInstance()->chunk_damaged(this, chunkid);
    }
}

void CChunkConn::chunks_lost(const uint8_t *data,uint32_t length)
{
    if (length%8!=0) {
        syslog(LOG_NOTICE,"CSTOMA_CHUNK_LOST - wrong size (%"PRIu32"/N*8)",length);
        this->mode=KILL;
        return;
    }
    if (length>0) {
        passert(data);
    }

    for (uint32_t i=0 ; i<length/8 ; i++) {
        uint64_t chunkid = get64bit(&data);
        CChunkMgr::getInstance()->chunk_lost(this, chunkid);
    }
}

void CChunkConn::chunks_new(const uint8_t *data,uint32_t length)
{
    if (length%12!=0) {
        syslog(LOG_NOTICE,"CSTOMA_CHUNK_NEW - wrong size (%"PRIu32"/N*12)",length);
        this->mode=KILL;
        return;
    }
    if (length>0) {
        passert(data);
    }
    for (uint32_t i=0 ; i<length/12 ; i++) {
        uint64_t chunkid = get64bit(&data);
        uint32_t chunkversion = get32bit(&data);
        CChunkMgr::getInstance()->chunk_server_has_chunk(this,chunkid,chunkversion);
    }
}

void CChunkConn::error_occurred(const uint8_t *data,uint32_t length)
{
    (void)data;
    if (length!=0) {
        syslog(LOG_NOTICE,"CSTOMA_ERROR_OCCURRED - wrong size (%"PRIu32"/0)",length);
        this->mode=KILL;
        return;
    }
    this->errorcounter++;
}

void CChunkConn::svr_space(const uint8_t *data,uint32_t length)
{
    if (length!=16 && length!=32 && length!=40) {
        syslog(LOG_NOTICE,"CSTOMA_SPACE - wrong size (%"PRIu32"/16|32|40)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    this->usedspace = get64bit(&data);
    this->totalspace = get64bit(&data);
    if (length==40) {
        this->chunkscount = get32bit(&data);
    }
    if (length>=32) {
        this->todelUsedSpace = get64bit(&data);
        this->todelTotalSpace = get64bit(&data);
        if (length==40) {
            this->todelChunksCount = get32bit(&data);
        }
    }
}

void CChunkConn::got_truncatechunk_status(const uint8_t *data,uint32_t length)
{
    if (length!=8+1) {
        syslog(LOG_NOTICE,"CSTOMA_TRUNCATE - wrong size (%"PRIu32"/9)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint8_t status = get8bit(&data);
    chunk_got_truncate_status(this,chunkid,status);
    if (status!=0) {
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" truncate status: %s",this->servstrip,this->servport,chunkid,mfsstrerr(status));
    }
}

void CChunkConn::got_deletechunk_status(const uint8_t *data,uint32_t length)
{
    if (length!=8+1) {
        syslog(LOG_NOTICE,"CSTOMA_DELETE - wrong size (%"PRIu32"/9)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint8_t status = get8bit(&data);
    this->delcounter--;
    CChunkMgr::getInstance()->got_delete_status(this,chunkid,status);
    if (status!=0) {
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" deletion status: %s",this->servstrip,this->servport,chunkid,mfsstrerr(status));
    }
}

void CChunkConn::got_createchunk_status(const uint8_t *data,uint32_t length)
{
    if (length!=8+1) {
        syslog(LOG_NOTICE,"CSTOMA_CREATE - wrong size (%"PRIu32"/9)",length);
        this->mode=KILL;
        return;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint8_t status = get8bit(&data);
    chunk_got_create_status(this,chunkid,status);
    if (status!=0) {
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" creation status: %s",this->servstrip,this->servport,chunkid,mfsstrerr(status));
    }
}

void CChunkConn::got_chunk_checksum(const uint8_t *data,uint32_t length)
{
    if (length!=8+4+1 && length!=8+4+4) {
        syslog(LOG_NOTICE,"CSTOAN_CHUNK_CHECKSUM - wrong size (%"PRIu32"/13|16)",length);
        this->mode=KILL;
        return ;
    }

    passert(data);
    uint64_t chunkid = get64bit(&data);
    uint32_t version = get32bit(&data);
    if (length==8+4+1) {
        uint8_t status = get8bit(&data);
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" calculate checksum status: %s",this->servstrip,this->servport,chunkid,mfsstrerr(status));
    } else {
        uint32_t checksum = get32bit(&data);
        syslog(LOG_NOTICE,"(%s:%"PRIu16") chunk: %016"PRIX64" calculate checksum: %08"PRIX32,this->servstrip,this->servport,chunkid,checksum);
    }
    (void)version;
}
