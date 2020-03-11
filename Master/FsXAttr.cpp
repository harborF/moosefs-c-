#include "FsXAttr.h"
#include "FsNode.h"

CFsXAttrData **CFsXAttrData::s_data_hash = NULL;

CFsXAttrData::CFsXAttrData()
{
}

CFsXAttrData::~CFsXAttrData()
{
}

void CFsXAttrData::release()
{
    *previnode = nextinode;
    if (nextinode) {
        nextinode->previnode = previnode;
    }
    *prev = next;
    if (next) {
        next->prev = prev;
    }
    free(attrname);
    if (attrvalue) {
        free(attrvalue);
    }
    delete(this);
}

void CFsXAttrData::xattr_dump()
{
    CFsXAttrData *xa;

    for (uint32_t i=0 ; i<XATTR_DATA_HASH_SIZE ; i++) {
        for (xa=s_data_hash[i] ; xa ; xa=xa->next) {
            printf("X|i:%10"PRIu32"|n:%s|v:%s\n",
                xa->inode,CFsNode::escape_name(xa->anleng,xa->attrname),CFsNode::escape_name(xa->avleng,xa->attrvalue));
        }
    }
}

uint8_t CFsXAttrData::getattr(uint32_t inode,
                      uint8_t anleng,const uint8_t *attrname,
                      uint32_t *avleng,uint8_t **attrvalue)
{
    CFsXAttrData *xa;
    for (xa = s_data_hash[data_hash_fn(inode,anleng,attrname)]; xa ; xa=xa->next) 
    {
        if (xa->inode==inode && xa->anleng==anleng && memcmp(xa->attrname,attrname,anleng)==0) {
            if (xa->avleng>MFS_XATTR_SIZE_MAX) {
                return ERROR_ERANGE;
            }
            *attrvalue = xa->attrvalue;
            *avleng = xa->avleng;
            return STATUS_OK;
        }
    }

    return ERROR_ENOATTR;
}

void CFsXAttrData::store_xattr(FILE *fd)
{
    uint8_t *ptr;
    uint8_t hdrbuff[4+1+4];
    CFsXAttrData *xa;

    for (uint32_t i=0 ; i<XATTR_DATA_HASH_SIZE ; i++)
    {
        for (xa=s_data_hash[i] ; xa ; xa=xa->next)
        {
            ptr = hdrbuff;
            put32bit(&ptr,xa->inode);
            put8bit(&ptr,xa->anleng);
            put32bit(&ptr,xa->avleng);
            if (fwrite(hdrbuff,1,4+1+4,fd)!=(size_t)(4+1+4)) {
                syslog(LOG_NOTICE,"fwrite error");
                return;
            }
            if (fwrite(xa->attrname,1,xa->anleng,fd)!=(size_t)(xa->anleng)) {
                syslog(LOG_NOTICE,"fwrite error");
                return;
            }
            if (xa->avleng>0) {
                if (fwrite(xa->attrvalue,1,xa->avleng,fd)!=(size_t)(xa->avleng)) {
                    syslog(LOG_NOTICE,"fwrite error");
                    return;
                }
            }
        }
    }

    memset(hdrbuff,0,4+1+4);
    if (fwrite(hdrbuff,1,4+1+4,fd)!=(size_t)(4+1+4)) {
        syslog(LOG_NOTICE,"fwrite error");
        return;
    }
}

//////////////////////////////////////////////////////////////////////////
CFsXAttrNode **CFsXAttrNode::s_inode_hash = NULL;

CFsXAttrNode::CFsXAttrNode()
{
}

CFsXAttrNode::~CFsXAttrNode()
{
}

void CFsXAttrNode::xattr_init(void) 
{
    uint32_t i;
    CFsXAttrData::s_data_hash = (CFsXAttrData**)malloc(sizeof(CFsXAttrData*)*XATTR_DATA_HASH_SIZE);
    passert(CFsXAttrData::s_data_hash);
    for (i=0 ; i<XATTR_DATA_HASH_SIZE ; i++) {
        CFsXAttrData::s_data_hash[i]=NULL;
    }

    CFsXAttrNode::s_inode_hash = (CFsXAttrNode**)malloc(sizeof(CFsXAttrNode*)*XATTR_INODE_HASH_SIZE);
    passert(CFsXAttrNode::s_inode_hash);
    for (i=0 ; i<XATTR_INODE_HASH_SIZE ; i++) {
        CFsXAttrNode::s_inode_hash[i]=NULL;
    }
}

void CFsXAttrNode::release(uint32_t inode)
{
    CFsXAttrNode *ih,**ihp;
    ihp = &(s_inode_hash[inode_hash_fn(inode)]);
    while ((ih = *ihp)) {
        if (ih->inode==inode) {
            while (ih->data_head) {
                ih->data_head->release();
            }
            *ihp = ih->next;
            SAFE_DELETE(ih);
        } else {
            ihp = &(ih->next);
        }
    }
}

uint8_t CFsXAttrNode::listattr_leng(uint32_t inode,void **xanode,uint32_t *xasize)
{
    CFsXAttrNode *ih;
    CFsXAttrData *xa;
    *xasize = 0;
    for (ih = s_inode_hash[inode_hash_fn(inode)]; ih ; ih=ih->next)
    {
        if (ih->inode==inode) {
            *xanode = ih;
            for (xa=ih->data_head ; xa ; xa=xa->nextinode) {
                *xasize += xa->anleng+1U;
            }
            if (*xasize>MFS_XATTR_LIST_MAX) {
                return ERROR_ERANGE;
            }
            return STATUS_OK;
        }
    }

    *xanode = NULL;
    return STATUS_OK;
}

uint8_t CFsXAttrNode::setattr(uint32_t inode,
                              uint8_t anleng,const uint8_t *attrname,
                              uint32_t avleng,const uint8_t *attrvalue,uint8_t mode) 
{
    CFsXAttrNode *ih;
    CFsXAttrData *xa;
    uint32_t hash,ihash;

    if (avleng>MFS_XATTR_SIZE_MAX) {
        return ERROR_ERANGE;
    }
#if MFS_XATTR_NAME_MAX<255
    if (anleng==0U || anleng>MFS_XATTR_NAME_MAX) {
#else
    if (anleng==0U) {
#endif
        return ERROR_EINVAL;
    }

    ihash = inode_hash_fn(inode);
    for (ih = s_inode_hash[ihash]; ih && ih->inode!=inode; ih=ih->next) {}

    hash = CFsXAttrData::data_hash_fn(inode,anleng,attrname);
    for (xa = CFsXAttrData::s_data_hash[hash]; xa ; xa=xa->next)
    {
        if (xa->inode==inode && xa->anleng==anleng && memcmp(xa->attrname,attrname,anleng)==0) {
            passert(ih);
            if (mode==MFS_XATTR_CREATE_ONLY) { // create only
                return ERROR_EEXIST;
            }

            if (mode==MFS_XATTR_REMOVE) { // remove
                ih->anleng -= anleng+1U;
                ih->avleng -= xa->avleng;
                xa->release();
                if (ih->data_head==NULL) {
                    if (ih->anleng!=0 || ih->avleng!=0) {
                        syslog(LOG_WARNING,"xattr non zero lengths on remove (inode:%"PRIu32",anleng:%"PRIu32",avleng:%"PRIu32")",
                            ih->inode,ih->anleng,ih->avleng);
                    }
                    release(inode);
                }
                return STATUS_OK;
            }

            ih->avleng -= xa->avleng;
            if (xa->attrvalue) {
                free(xa->attrvalue);
            }

            if (avleng>0) {
                xa->attrvalue = (uint8_t*)malloc(avleng);
                passert(xa->attrvalue);
                memcpy(xa->attrvalue,attrvalue,avleng);
            } else {
                xa->attrvalue = NULL;
            }

            xa->avleng = avleng;
            ih->avleng += avleng;

            return STATUS_OK;
        }
    }

    if (mode==MFS_XATTR_REPLACE_ONLY || mode==MFS_XATTR_REMOVE) {
        return ERROR_ENOATTR;
    }

    if (ih && ih->anleng+anleng+1>MFS_XATTR_LIST_MAX) {
        return ERROR_ERANGE;
    }

    xa = new CFsXAttrData();
    passert(xa);
    xa->inode = inode;
    xa->attrname = (uint8_t*)malloc(anleng);
    passert(xa->attrname);
    memcpy(xa->attrname,attrname,anleng);
    xa->anleng = anleng;
    if (avleng>0) {
        xa->attrvalue = (uint8_t*)malloc(avleng);
        passert(xa->attrvalue);
        memcpy(xa->attrvalue,attrvalue,avleng);
    } else {
        xa->attrvalue = NULL;
    }

    xa->avleng = avleng;
    xa->next = CFsXAttrData::s_data_hash[hash];
    if (xa->next) {
        xa->next->prev = &(xa->next);
    }

    xa->prev = CFsXAttrData::s_data_hash + hash;
    CFsXAttrData::s_data_hash[hash] = xa;

    if (ih) {
        xa->nextinode = ih->data_head;
        if (xa->nextinode) {
            xa->nextinode->previnode = &(xa->nextinode);
        }
        xa->previnode = &(ih->data_head);
        ih->data_head = xa;
        ih->anleng += anleng+1U;
        ih->avleng += avleng;
    } else {
        ih = new CFsXAttrNode();
        passert(ih);
        ih->inode = inode;
        xa->nextinode = NULL;
        xa->previnode = &(ih->data_head);
        ih->data_head = xa;
        ih->anleng = anleng+1U;
        ih->avleng = avleng;
        ih->next = s_inode_hash[ihash];
        s_inode_hash[ihash] = ih;
    }

    return STATUS_OK;
}

int CFsXAttrNode::load_xattr(FILE *fd,int ignoreflag)
{
    uint8_t hdrbuff[4+1+4];
    const uint8_t *ptr;
    uint32_t inode;
    uint8_t anleng;
    uint32_t avleng;
    uint8_t nl=1;
    CFsXAttrData *xa;
    CFsXAttrNode *ih;
    uint32_t hash,ihash;

    while (1) {
        if (fread(hdrbuff,1,4+1+4,fd)!=4+1+4) {
            int err = errno;
            if (nl) {
                fputc('\n',stderr);
                // nl=0;
            }
            errno = err;
            mfs_errlog(LOG_ERR,"loading xattr: read error");
            return -1;
        }
        ptr = hdrbuff;
        inode = get32bit(&ptr);
        anleng = get8bit(&ptr);
        avleng = get32bit(&ptr);
        if (inode==0) {
            return 1;
        }
        if (anleng==0) {
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            mfs_syslog(LOG_ERR,"loading xattr: empty name");
            if (ignoreflag) {
                fseek(fd,anleng+avleng,SEEK_CUR);
                continue;
            } else {
                return -1;
            }
        }
        if (avleng>MFS_XATTR_SIZE_MAX) {
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            mfs_syslog(LOG_ERR,"loading xattr: value oversized");
            if (ignoreflag) {
                fseek(fd,anleng+avleng,SEEK_CUR);
                continue;
            } else {
                return -1;
            }
        }

        ihash = inode_hash_fn(inode);
        for (ih = s_inode_hash[ihash]; ih && ih->inode!=inode; ih=ih->next) {}

        if (ih && ih->anleng+anleng+1>MFS_XATTR_LIST_MAX) {
            if (nl) {
                fputc('\n',stderr);
                nl=0;
            }
            mfs_syslog(LOG_ERR,"loading xattr: name list too long");
            if (ignoreflag) {
                fseek(fd,anleng+avleng,SEEK_CUR);
                continue;
            } else {
                return -1;
            }
        }

        xa = new CFsXAttrData();
        passert(xa);
        xa->inode = inode;
        xa->attrname = (uint8_t*)malloc(anleng);
        passert(xa->attrname);
        if (fread(xa->attrname,1,anleng,fd)!=(size_t)anleng) {
            int err = errno;
            if (nl) {
                fputc('\n',stderr);
                // nl=0;
            }

            free(xa->attrname);
            SAFE_DELETE(xa);
            errno = err;
            mfs_errlog(LOG_ERR,"loading xattr: read error");

            return -1;
        }

        xa->anleng = anleng;
        if (avleng>0) {
            xa->attrvalue = (uint8_t*)malloc(avleng);
            passert(xa->attrvalue);
            if (fread(xa->attrvalue,1,avleng,fd)!=(size_t)avleng) {
                int err = errno;
                if (nl) {
                    fputc('\n',stderr);
                    // nl=0;
                }
                free(xa->attrname);
                free(xa->attrvalue);
                SAFE_DELETE(xa);
                errno = err;
                mfs_errlog(LOG_ERR,"loading xattr: read error");
                return -1;
            }
        } else {
            xa->attrvalue = NULL;
        }

        xa->avleng = avleng;
        hash = CFsXAttrData::data_hash_fn(inode,xa->anleng,xa->attrname);
        xa->next = CFsXAttrData::s_data_hash[hash];
        if (xa->next) {
            xa->next->prev = &(xa->next);
        }
        xa->prev = CFsXAttrData::s_data_hash + hash;
        CFsXAttrData::s_data_hash[hash] = xa;

        if (ih) {
            xa->nextinode = ih->data_head;
            if (xa->nextinode) {
                xa->nextinode->previnode = &(xa->nextinode);
            }
            xa->previnode = &(ih->data_head);
            ih->data_head = xa;
            ih->anleng += anleng+1U;
            ih->avleng += avleng;
        } else {
            ih = new CFsXAttrNode();
            passert(ih);
            ih->inode = inode;
            xa->nextinode = NULL;
            xa->previnode = &(ih->data_head);
            ih->data_head = xa;
            ih->anleng = anleng+1U;
            ih->avleng = avleng;
            ih->next = s_inode_hash[ihash];
            s_inode_hash[ihash] = ih;
        }
    }
}
