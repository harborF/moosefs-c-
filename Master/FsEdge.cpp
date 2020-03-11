#include "FsEdge.h"
#include "FsNode.h"
#include "FileSysMgr.h"

CFsEdge* CFsEdge::s_trash = NULL;
CFsEdge* CFsEdge::s_reserved = NULL;
CFsEdge* CFsEdge::s_edgehash[EDGEHASHSIZE];

CFsEdge::CFsEdge()
{
}

CFsEdge::~CFsEdge()
{
}

void CFsEdge::dump()
{
    if (parent==NULL) 
    {
        if (child->type==TYPE_TRASH) {
            printf("E|p:     TRASH|c:%10"PRIu32"|n:%s\n", child->id,CFsNode::escape_name(nleng,name));
        } else if (child->type==TYPE_RESERVED) {
            printf("E|p:  RESERVED|c:%10"PRIu32"|n:%s\n", child->id,CFsNode::escape_name(nleng,name));
        } else {
            printf("E|p:      NULL|c:%10"PRIu32"|n:%s\n", child->id,CFsNode::escape_name(nleng,name));
        }
    }
    else
    {
        printf("E|p:%10"PRIu32"|c:%10"PRIu32"|n:%s\n", parent->id,child->id,CFsNode::escape_name(nleng,name));
    }
}

uint32_t CFsEdge::get_path_size()
{
    CFsNode *p = this->parent;
    uint32_t size = this->nleng;

    while (p!=CFsNode::s_root && p->parents) {
        size += p->parents->nleng+1;
        p = p->parents->parent;
    }

    return size;
}

void CFsEdge::get_path(uint16_t *pleng,uint8_t **path)
{
    uint32_t size = get_path_size();
    if (size>65535) {
        syslog(LOG_WARNING,"path too long !!! - truncate");
        size=65535;
    }

    *pleng = size;
    uint8_t *ret = (uint8_t *)malloc(size);
    passert(ret);
    size -= this->nleng;
    memcpy(ret+size,this->name,this->nleng);
    if (size>0) {
        ret[--size]='/';
    }

    CFsNode *p = this->parent;
    while (p!=CFsNode::s_root && p->parents) {
        if (size>=p->parents->nleng) {
            size-=p->parents->nleng;
            memcpy(ret+size,p->parents->name,p->parents->nleng);
        } else {
            if (size>0) {
                memcpy(ret,p->parents->name+(p->parents->nleng-size),size);
                size=0;
            }
        }
        if (size>0) {
            ret[--size]='/';
        }
        p = p->parents->parent;
    }
    *path = ret;
}

void CFsEdge::get_path_data(uint8_t *path,uint32_t size)
{
    if (size>=this->nleng) {
        size-=this->nleng;
        memcpy(path+size,this->name,this->nleng);
    } else if (size>0) {
        memcpy(path,this->name+(this->nleng-size),size);
        size=0;
    }

    if (size>0) {
        path[--size]='/';
    }

    CFsNode *p = this->parent;
    while (p!=CFsNode::s_root && p->parents) {
        if (size>=p->parents->nleng) {
            size-=p->parents->nleng;
            memcpy(path+size,p->parents->name,p->parents->nleng);
        } else if (size>0) {
            memcpy(path,p->parents->name+(p->parents->nleng-size),size);
            size=0;
        }
        if (size>0) {
            path[--size]='/';
        }
        p = p->parents->parent;
    }
}

uint32_t CFsEdge::get_detached_size()
{
    uint32_t result=0;
    for (CFsEdge *e = this ; e ; e=e->nextChild)
    {
        if (e->nleng>240) {
            result+=245;
        } else {
            result+=5+e->nleng;
        }
    }
    return result;
}

void CFsEdge::get_detached_data(uint8_t *dbuff)
{
    uint8_t *sptr;
    uint8_t c;
    for ( CFsEdge *e = this ; e ; e=e->nextChild)
    {
        if (e->nleng>240) {
            *dbuff=240;
            dbuff++;
            memcpy(dbuff,"(...)",5);
            dbuff+=5;
            sptr = e->name+(e->nleng-235);
            for (c=0 ; c<235 ; c++) {
                if (*sptr=='/') {
                    *dbuff='|';
                } else {
                    *dbuff = *sptr;
                }
                sptr++;
                dbuff++;
            }
        } else {
            *dbuff=e->nleng;
            dbuff++;
            sptr = e->name;
            for (c=0 ; c<e->nleng ; c++) {
                if (*sptr=='/') {
                    *dbuff='|';
                } else {
                    *dbuff = *sptr;
                }
                sptr++;
                dbuff++;
            }
        }
        put32bit(&dbuff,e->child->id);
    }
}

CFsEdge* CFsEdge::new_edge(uint8_t type, uint32_t pleng, uint8_t *path, CFsNode* pChild)
{
    sassert(type == TYPE_RESERVED || type == TYPE_TRASH);

    CFsEdge* e = (CFsEdge*)malloc(sizeof(CFsEdge));
    passert(e);
    e->nleng = pleng;
    e->name = path;
    e->child = pChild;
    e->parent = NULL;
    e->nextParent = NULL;
    e->prevParent = &(pChild->parents);

#ifdef EDGEHASH
    e->next = NULL;
    e->prev = NULL;
#endif  

    if (type == TYPE_RESERVED)
    {
        e->nextChild = s_reserved;
        e->prevChild = &s_reserved;
        if (e->nextChild) {
            e->nextChild->prevChild = &(e->nextChild);
        } 

        s_reserved = e;
        pChild->parents = e;
        CFileSysMgr::s_reservedspace += pChild->data.fdata.length;
        CFileSysMgr::s_reservednodes++;
    }
    else if (type == TYPE_TRASH)
    {
        e->nextChild = s_trash;
        e->prevChild = &s_trash;
        if (e->nextChild) {
            e->nextChild->prevChild = &(e->nextChild);
        }

        s_trash = e;
        pChild->parents = e;
        CFileSysMgr::s_trashspace += pChild->data.fdata.length;
        CFileSysMgr::s_trashnodes++;
    } 

    return e;
}

CFsEdge* CFsEdge::new_edge(CFsNode *parent,CFsNode *child,uint16_t nleng,const uint8_t *name)
{
    CFsEdge*e = (CFsEdge*)malloc(sizeof(CFsEdge));
    passert(e);

    e->nleng = nleng;
    e->name = (uint8_t*)malloc(nleng);
    passert(e->name);
    memcpy(e->name,name,nleng);

    e->child = child;
    e->parent = parent;
    e->nextChild = parent->data.ddata.children;
    if (e->nextChild) {
        e->nextChild->prevChild = &(e->nextChild);
    }

    parent->data.ddata.children = e;
    e->prevChild = &(parent->data.ddata.children);
    e->nextParent = child->parents;
    if (e->nextParent) {
        e->nextParent->prevParent = &(e->nextParent);
    }

    child->parents = e;
    e->prevParent = &(child->parents);
    parent->data.ddata.elements++;
    if (child->type==TYPE_DIRECTORY) {
        parent->data.ddata.nlink++;
    }

#ifdef EDGEHASH
    uint32_t hpos = EDGEHASHPOS(CFsNode::fsnodes_hash(parent->id,nleng,name));
    e->next = s_edgehash[hpos];
    if (e->next) {
        e->next->prev = &(e->next);
    }
    s_edgehash[hpos] = e;
    e->prev = &(s_edgehash[hpos]);
#endif

    return e;
}

void CFsEdge::remove_edge(uint32_t ts)
{
#ifndef METARESTORE
    STStatsRec sr;
#endif
    if (this->parent) {
#ifndef METARESTORE
        this->child->get_stats(&sr);
        this->parent->sub_stats(&sr);
#endif
        this->parent->mtime = this->parent->ctime = ts;
        this->parent->data.ddata.elements--;
        if (this->child->type==TYPE_DIRECTORY) {
            this->parent->data.ddata.nlink--;
        }
    }

    if (this->child) {
        this->child->ctime = ts;
    }
    *(this->prevChild) = this->nextChild;
    if (this->nextChild) {
        this->nextChild->prevChild = this->prevChild;
    }

    *(this->prevParent) = this->nextParent;
    if (this->nextParent) {
        this->nextParent->prevParent = this->prevParent;
    }
#ifdef EDGEHASH
    if (this->prev) {
        *(this->prev) = this->next;
        if (this->next) {
            this->next->prev = this->prev;
        }
    }
#endif
    free(this->name);
    free(this);
}

