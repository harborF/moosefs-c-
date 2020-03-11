#include "MetaLoggerConn.h"
#include <unistd.h>
#include <sys/uio.h>
#include <fcntl.h>
#include "crc.h"
#include "ServerCore.h"
#include "slogger.h"

CMetaLoggerConn* CMetaLoggerConn::s_pServHead = NULL;
uint16_t CMetaLoggerConn::s_changelog_save = 0;
old_changes_block* CMetaLoggerConn::s_old_changes_head = NULL;
old_changes_block* CMetaLoggerConn::s_old_changes_current = NULL;

uint32_t CMetaLoggerConn::mloglist_size(void)
{
    uint32_t i = 0;
    CMetaLoggerConn *eptr;
    for (eptr = s_pServHead; eptr ; eptr=eptr->next) {
        if (eptr->mode!=KILL) {
            i++;
        }
    }
    return i*(4+4);
}

void CMetaLoggerConn::mloglist_data(uint8_t *ptr)
{
    CMetaLoggerConn *eptr;
    for (eptr = s_pServHead ; eptr ; eptr=eptr->next) {
        if (eptr->mode!=KILL) {
            put32bit(&ptr,eptr->version);
            put32bit(&ptr,eptr->servip);
        }
    }
}

void CMetaLoggerConn::serv_status(void)
{
    CMetaLoggerConn *eptr;
    for (eptr = s_pServHead ; eptr ; eptr=eptr->next) {
        if (eptr->mode==HEADER || eptr->mode==DATA) {
            return;
        }
    }
    syslog(LOG_WARNING,"no meta loggers connected !!!");
}

void CMetaLoggerConn::beforeclose()
{
    if (this->metafd>=0) {
        close(this->metafd);
        this->metafd=-1;
    }
    if (this->chain1fd>=0) {
        close(this->chain1fd);
        this->chain1fd=-1;
    }
    if (this->chain2fd>=0) {
        close(this->chain2fd);
        this->chain2fd=-1;
    }
}

void CMetaLoggerConn::send_old_changes(uint64_t version)
{
    if (s_old_changes_head==NULL) {
        return;
    }

    if (s_old_changes_head->minversion>version) {
        syslog(LOG_WARNING,"meta logger wants changes since version: %"PRIu64", but minimal version in storage is: %"PRIu64,
            version,s_old_changes_head->minversion);
        return;
    }

    uint32_t i; 
    uint8_t *data, start=0;
    old_changes_entry *oce;

    for (old_changes_block *oc=s_old_changes_head ; oc ; oc=oc->next) 
    {
        if (oc->minversion<=version && (oc->next==NULL || oc->next->minversion>version)) {
            start=1;
        }

        if (start) {
            for (i=0 ; i<oc->entries ; i++) {
                oce = oc->old_blocks + i;
                if (version>=oce->version) {
                    data = this->createPacket(MATOML_METACHANGES_LOG,9+oce->length);
                    put8bit(&data,0xFF);
                    put64bit(&data,oce->version);
                    memcpy(data,oce->data,oce->length);
                }
            }
        }
    }
}

void CMetaLoggerConn::old_changes_free_block(old_changes_block *oc) 
{
    uint32_t i;
    for (i=0 ; i<oc->entries ; i++) {
        free(oc->old_blocks[i].data);
    }
    free(oc);
}

void CMetaLoggerConn::store_logstring(uint64_t version,uint8_t *logstr,uint32_t logstrsize)
{
    old_changes_block *oc;
    old_changes_entry *oce;
    uint32_t ts;
    if (s_changelog_save==0) {
        while (s_old_changes_head) {
            oc = s_old_changes_head->next;
            old_changes_free_block(s_old_changes_head);
            s_old_changes_head = oc;
        }

        return;
    }

    if (s_old_changes_current==NULL || s_old_changes_head==NULL 
        || s_old_changes_current->entries>=OLD_CHANGES_BLOCK_SIZE)
    {
        oc = (old_changes_block*)malloc(sizeof(old_changes_block));
        passert(oc);
        ts = CServerCore::get_time();
        oc->entries = 0;
        oc->minversion = version;
        oc->mintimestamp = ts;
        oc->next = NULL;

        if (s_old_changes_current==NULL || s_old_changes_head==NULL) {
            s_old_changes_head = s_old_changes_current = oc;
        } else {
            s_old_changes_current->next = oc;
            s_old_changes_current = oc;
        }

        while (s_old_changes_head && s_old_changes_head->next 
            && s_old_changes_head->next->mintimestamp+s_changelog_save<ts)
        {
            oc = s_old_changes_head->next;
            old_changes_free_block(s_old_changes_head);
            s_old_changes_head = oc;
        }
    }

    oc = s_old_changes_current;
    oce = oc->old_blocks + oc->entries;
    oce->version = version;
    oce->length = logstrsize;
    oce->data = (uint8_t*)malloc(logstrsize);
    passert(oce->data);
    memcpy(oce->data,logstr,logstrsize);
    oc->entries++;
}

void CMetaLoggerConn::serv_register(const uint8_t *data,uint32_t length)
{
    uint8_t rversion;
    uint64_t minversion;

    if (this->version>0) {
        syslog(LOG_WARNING,"got register message from registered metalogger !!!");
        this->mode=KILL;
        return;
    }

    if (length<1) {
        syslog(LOG_NOTICE,"MLTOMA_REGISTER - wrong size (%"PRIu32")",length);
        this->mode=KILL;
        return;
    } else {
        rversion = get8bit(&data);
        if (rversion==1) {
            if (length!=7) {
                syslog(LOG_NOTICE,"MLTOMA_REGISTER (ver 1) - wrong size (%"PRIu32"/7)",length);
                this->mode=KILL;
                return;
            }
            this->version = get32bit(&data);
            this->timeout = get16bit(&data);
        } else if (rversion==2) {
            if (length!=7+8) {
                syslog(LOG_NOTICE,"MLTOMA_REGISTER (ver 2) - wrong size (%"PRIu32"/15)",length);
                this->mode=KILL;
                return;
            }
            this->version = get32bit(&data);
            this->timeout = get16bit(&data);
            minversion = get64bit(&data);
            send_old_changes(minversion);
        } else {
            syslog(LOG_NOTICE,"MLTOMA_REGISTER - wrong version (%"PRIu8"/1)",rversion);
            this->mode=KILL;
            return;
        }

        if (this->timeout<10) {
            syslog(LOG_NOTICE,"MLTOMA_REGISTER communication timeout too small (%"PRIu16" seconds - should be at least 10 seconds)",this->timeout);
            if (this->timeout<3) {
                this->timeout=3;
            }
            return;
        }
    }
}

void CMetaLoggerConn::download_start(const uint8_t *data,uint32_t length)
{
    if (length!=1) {
        syslog(LOG_NOTICE,"MLTOMA_DOWNLOAD_START - wrong size (%"PRIu32"/1)",length);
        this->mode=KILL;
        return;
    }

    uint8_t filenum = get8bit(&data);
    if (filenum==1 || filenum==2) {
        if (this->metafd>=0) {
            close(this->metafd);
            this->metafd=-1;
        }
        if (this->chain1fd>=0) {
            close(this->chain1fd);
            this->chain1fd=-1;
        }
        if (this->chain2fd>=0) {
            close(this->chain2fd);
            this->chain2fd=-1;
        }
    }
    if (filenum==1) {
        this->metafd = open("metadata.mfs.back",O_RDONLY);
        this->chain1fd = open("changelog.0.mfs",O_RDONLY);
        this->chain2fd = open("changelog.1.mfs",O_RDONLY);
    } else if (filenum==2) {
        this->metafd = open("sessions.mfs",O_RDONLY);
    } else if (filenum==11) {
        if (this->metafd>=0) {
            close(this->metafd);
        }
        this->metafd = this->chain1fd;
        this->chain1fd = -1;
    } else if (filenum==12) {
        if (this->metafd>=0) {
            close(this->metafd);
        }
        this->metafd = this->chain2fd;
        this->chain2fd = -1;
    } else {
        this->mode=KILL;
        return;
    }

    uint8_t *ptr;
    if (this->metafd<0) {
        if (filenum==11 || filenum==12) {
            ptr = this->createPacket(MATOML_DOWNLOAD_START,8);
            put64bit(&ptr,0);
            return;
        } else {
            ptr = this->createPacket(MATOML_DOWNLOAD_START,1);
            put8bit(&ptr,0xff);	// error
            return;
        }
    }

    uint64_t size = lseek(this->metafd,0,SEEK_END);
    ptr = this->createPacket(MATOML_DOWNLOAD_START,8);
    put64bit(&ptr,size);	// ok
}

void CMetaLoggerConn::download_data(const uint8_t *data,uint32_t length)
{
    if (length!=12) {
        syslog(LOG_NOTICE,"MLTOMA_DOWNLOAD_DATA - wrong size (%"PRIu32"/12)",length);
        this->mode=KILL;
        return;
    }
    if (this->metafd<0) {
        syslog(LOG_NOTICE,"MLTOMA_DOWNLOAD_DATA - file not opened");
        this->mode=KILL;
        return;
    }

    uint64_t offset = get64bit(&data);
    uint32_t leng = get32bit(&data);
    uint8_t *ptr = this->createPacket(MATOML_DOWNLOAD_DATA,16+leng);
    put64bit(&ptr,offset);
    put32bit(&ptr,leng);
#ifdef HAVE_PREAD
    ssize_t ret = pread(this->metafd,ptr+4,leng,offset);
#else /* HAVE_PWRITE */
    lseek(this->metafd,offset,SEEK_SET);
    ssize_t ret = read(this->metafd,ptr+4,leng);
#endif /* HAVE_PWRITE */
    if (ret!=(ssize_t)leng) {
        mfs_errlog_silent(LOG_NOTICE,"error reading metafile");
        this->mode=KILL;
        return;
    }
    uint32_t crc = mycrc32(0,ptr+4,leng);
    put32bit(&ptr,crc);
}

void CMetaLoggerConn::download_end(const uint8_t *data,uint32_t length)
{
    (void)data;
    if (length!=0) {
        syslog(LOG_NOTICE,"MLTOMA_DOWNLOAD_END - wrong size (%"PRIu32"/0)",length);
        this->mode=KILL;
        return;
    }
    if (this->metafd>=0) {
        close(this->metafd);
        this->metafd=-1;
    }
}
