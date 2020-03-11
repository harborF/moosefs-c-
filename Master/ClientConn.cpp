#include "ClientConn.h"
#include "charts.h"
#include "ChartsData.h"

STSession* CClientConn::s_pSessHead=NULL;
CClientConn* CClientConn::s_pConnHead = NULL;
uint32_t CClientConn::s_SessSustainTime = 0;

int CClientConn::s_exiting = 0;
int CClientConn::s_starting= 0;
uint32_t CClientConn::s_RejectOld = 0;

void CClientConn::before_disconnect() 
{
    chunklist *cl,*acl;
    cl=this->chunkDelayedOps;
    while (cl) {
        acl = cl;
        cl=cl->next;
        if (acl->type == FUSE_TRUNCATE) {
            fs_end_setlength(acl->chunkid);
        }
        free(acl);
    }

    this->chunkDelayedOps=NULL;
    if (this->sesData) {
        if (this->sesData->nsocks>0) {
            this->sesData->nsocks--;
        }

        if (this->sesData->nsocks==0) {
            this->sesData->disconnected = CServerCore::get_time();
        }
    }
}

int CClientConn::insert_openfile(STSession* cr,uint32_t inode)
{
    filelist *ofptr,**ofpptr;
    int status;

    ofpptr = &(cr->openedfiles);
    while ((ofptr=*ofpptr)) {
        if (ofptr->inode==inode) {
            return STATUS_OK;	// file already acquired - nothing to do
        }
        if (ofptr->inode>inode) {
            break;
        }
        ofpptr = &(ofptr->next);
    }

    status = fs_acquire(inode,cr->sessionid);
    if (status==STATUS_OK) {
        ofptr = (filelist*)malloc(sizeof(filelist));
        passert(ofptr);
        ofptr->inode = inode;
        ofptr->next = *ofpptr;
        *ofpptr = ofptr;
    }

    return status;
}

void CClientConn::ugid_remap(uint32_t *auid,uint32_t *agid)
{
    if (*auid==0) {
        *auid = this->sesData->rootuid;
        if (agid) {
            *agid = this->sesData->rootgid;
        }
    } else if (this->sesData->sesflags&SESFLAG_MAPALL) {
        *auid = this->sesData->mapalluid;
        if (agid) {
            *agid = this->sesData->mapallgid;
        }
    }
}

void CClientConn::cserv_list(const uint8_t *data,uint32_t length)
{
    (void)data;
    if (length!=0) {
        syslog(LOG_NOTICE,"CLTOMA_CSERV_LIST - wrong size (%"PRIu32"/0)",length);
        this->mode = KILL;
        return;
    }

    uint8_t *ptr = this->createPacket(MATOCL_CSERV_LIST, CChunkSvrMgr::getInstance()->get_svrlist_size());
    CChunkSvrMgr::getInstance()->get_svrlist_data(ptr);
}

void CClientConn::cserv_removeserv(const uint8_t *data,uint32_t length)
{
    if (length!=6) {
        syslog(LOG_NOTICE,"CLTOMA_CSSERV_REMOVESERV - wrong size (%"PRIu32"/6)",length);
        this->mode = KILL;
        return;
    }

    uint32_t ip = get32bit(&data);
    uint16_t port = get16bit(&data);

    CChunkSvrMgr::getInstance()->remove_server(ip,port);
    this->createPacket(MATOCL_CSSERV_REMOVESERV,0);
}

void CClientConn::serv_chart(const uint8_t *data,uint32_t length)
{
    if (length!=4) {
        syslog(LOG_NOTICE,"CLTOAN_CHART - wrong size (%"PRIu32"/4)",length);
        this->mode = KILL;
        return;
    }

    uint32_t chartid = get32bit(&data);
    uint32_t l = charts_make_png(chartid);
    uint8_t *ptr = this->createPacket(ANTOCL_CHART,l);
    if (l>0) {
        charts_get_png(ptr);
    }
}

void CClientConn::chart_data(const uint8_t *data,uint32_t length) 
{
    if (length!=4) {
        syslog(LOG_NOTICE,"CLTOAN_CHART_DATA - wrong size (%"PRIu32"/4)",length);
        this->mode = KILL;
        return;
    }

    uint32_t chartid = get32bit(&data);
    uint32_t l = charts_datasize(chartid);
    uint8_t *ptr = this->createPacket(ANTOCL_CHART_DATA,l);
    if (l>0) {
        charts_makedata(ptr,chartid);
    }
}

void CClientConn::serv_info(const uint8_t *data,uint32_t length)
{
    if (length!=0) {
        syslog(LOG_NOTICE,"CLTOMA_INFO - wrong size (%"PRIu32"/0)",length);
        this->mode = KILL;
        return;
    }

    uint64_t totalspace,availspace,trspace,respace;
    uint32_t trnodes,renodes,inodes,dnodes,fnodes;
    CFileSysMgr::fs_info(&totalspace,&availspace,&trspace,&trnodes,&respace,&renodes,&inodes,&dnodes,&fnodes);

    uint32_t chunks,chunkcopies,tdcopies;
    CFileSysMgr::chunk_info(&chunks,&chunkcopies,&tdcopies);
    uint64_t memusage = chartsdata_memusage();

    uint8_t *ptr = this->createPacket(MATOCL_INFO,76);
    put16bit(&ptr,VERSMAJ);
    put8bit(&ptr,VERSMID);
    put8bit(&ptr,VERSMIN);
    /* --- */
    put64bit(&ptr,memusage);
    /* --- */
    put64bit(&ptr,totalspace);
    put64bit(&ptr,availspace);
    put64bit(&ptr,trspace);
    put32bit(&ptr,trnodes);
    put64bit(&ptr,respace);
    put32bit(&ptr,renodes);
    put32bit(&ptr,inodes);
    put32bit(&ptr,dnodes);
    put32bit(&ptr,fnodes);
    put32bit(&ptr,chunks);
    put32bit(&ptr,chunkcopies);
    put32bit(&ptr,tdcopies);
}

void CClientConn::fstest_info(const uint8_t *data,uint32_t length) 
{
    if (length!=0) {
        syslog(LOG_NOTICE,"CLTOMA_FSTEST_INFO - wrong size (%"PRIu32"/0)",length);
        this->mode = KILL;
        return;
    }

    char *msgbuff;
    uint32_t loopstart,loopend,files,ugfiles,mfiles,chunks,ugchunks,mchunks,msgbuffleng;
    fs_test_getdata(&loopstart,&loopend,&files,&ugfiles,&mfiles,&chunks,&ugchunks,&mchunks,&msgbuff,&msgbuffleng);

    uint8_t *ptr = this->createPacket(MATOCL_FSTEST_INFO,msgbuffleng+36);
    put32bit(&ptr,loopstart);
    put32bit(&ptr,loopend);
    put32bit(&ptr,files);
    put32bit(&ptr,ugfiles);
    put32bit(&ptr,mfiles);
    put32bit(&ptr,chunks);
    put32bit(&ptr,ugchunks);
    put32bit(&ptr,mchunks);
    put32bit(&ptr,msgbuffleng);
    if (msgbuffleng>0) {
        memcpy(ptr,msgbuff,msgbuffleng);
    }
}

void CClientConn::chunkstest_info(const uint8_t *data,uint32_t length)
{
    if (length!=0) {
        syslog(LOG_NOTICE,"CLTOMA_CHUNKSTEST_INFO - wrong size (%"PRIu32"/0)",length);
        this->mode = KILL;
        return;
    }

    uint8_t *ptr = this->createPacket(MATOCL_CHUNKSTEST_INFO,52);
    chunk_store_info(ptr);
}

void CClientConn::chunks_matrix(const uint8_t *data,uint32_t length)
{
    if (length>1) {
        syslog(LOG_NOTICE,"CLTOMA_CHUNKS_MATRIX - wrong size (%"PRIu32"/0|1)",length);
        this->mode = KILL;
        return;
    }

    uint8_t matrixid;
    if (length==1) {
        matrixid = get8bit(&data);
    } else {
        matrixid = 0;
    }

    uint8_t *ptr = this->createPacket(MATOCL_CHUNKS_MATRIX, 484);
    CFileSysMgr::get_store_chunks_counters(ptr, matrixid);
}

void CClientConn::quota_info(const uint8_t *data,uint32_t length)
{
    if (length!=0) {
        syslog(LOG_NOTICE,"CLTOMA_QUOTA_INFO - wrong size (%"PRIu32"/0)",length);
        this->mode = KILL;
        return;
    }

    uint8_t *ptr = this->createPacket(MATOCL_QUOTA_INFO,fs_getquotainfo_size());
    fs_getquotainfo_data(ptr);
}

void CClientConn::exports_info(const uint8_t *data,uint32_t length)
{
    if (length!=0 && length!=1) {
        syslog(LOG_NOTICE,"CLTOMA_EXPORTS_INFO - wrong size (%"PRIu32"/0|1)",length);
        this->mode = KILL;
        return;
    }

    uint8_t vmode;
    if (length==0) {
        vmode = 0;
    } else {
        vmode = get8bit(&data);
    }

    uint8_t *ptr = this->createPacket(MATOCL_EXPORTS_INFO,exports_info_size(vmode));
    exports_info_data(vmode,ptr);
}

void CClientConn::mlog_list(const uint8_t *data,uint32_t length)
{
    (void)data;
    if (length!=0) {
        syslog(LOG_NOTICE,"CLTOMA_MLOG_LIST - wrong size (%"PRIu32"/0)",length);
        this->mode = KILL;
        return;
    }

    uint8_t *ptr = this->createPacket(MATOCL_MLOG_LIST, CMetaLoggerConn::mloglist_size());
    CMetaLoggerConn::mloglist_data(ptr);
}
