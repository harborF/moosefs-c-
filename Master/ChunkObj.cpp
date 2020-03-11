#include "ChunkObj.h"
#include "ChunkMgr.h"
#include "ChunkCtrl.h"
#include "mfsFactory.h"
#include "ClientCtrl.h"
#include "FileSysOpr.h"

void CChunkObj::clear()
{
#ifndef USE_SLIST_BUCKETS
    slist *sl,*sln;
    for (sl = slisthead ; sl ; sl = sln) {
        sln = sl->next;
        free(sl);
    }
# endif
}

int CChunkObj::delete_file_int(uint8_t goal)
{
    if (this->fcount==0) {
#ifndef METARESTORE
        syslog(LOG_WARNING,"serious structure inconsistency: (chunkid:%016"PRIX64")",this->chunkid);
#else
        printf("serious structure inconsistency: (chunkid:%016"PRIX64")\n",this->chunkid);
#endif
        return ERROR_CHUNKLOST;	// ERROR_STRUCTURE
    }

#ifndef METARESTORE
    uint8_t oldgoal = this->goal;
#endif

    if (this->fcount==1) {
        this->goal = 0;
        this->fcount = 0;
    } else {
        if (this->ftab) {
            this->ftab[goal]--;
            this->goal = 9;
            while (this->ftab[this->goal]==0) {
                this->goal--;
            }
        }
        this->fcount--;
        if (this->fcount==1 && this->ftab) {
            free(this->ftab);
            this->ftab = NULL;
        }
    }

#ifndef METARESTORE
    if (oldgoal!=this->goal) {
        chunk_state_change(oldgoal,goal,allValidCopies,allValidCopies,rValidCopies,rValidCopies);
    }
#endif

    return STATUS_OK;
}

int CChunkObj::add_file_int(uint8_t goal)
{
#ifndef METARESTORE
    uint8_t oldgoal = this->goal;
#endif

    if (this->fcount==0) {
        this->goal = goal;
        this->fcount = 1;
    } else if (goal==this->goal) {
        this->fcount++;
        if (this->ftab) {
            this->ftab[goal]++;
        }
    } else {
        if (this->ftab==NULL) {
            this->ftab = (uint32_t*)malloc(sizeof(uint32_t)*10);
            passert(this->ftab);
            memset(this->ftab,0,sizeof(uint32_t)*10);
            this->ftab[this->goal]=this->fcount;
            this->ftab[goal]=1;
            this->fcount++;
            if (goal > this->goal) {
                this->goal = goal;
            }
        } else {
            this->ftab[goal]++;
            this->fcount++;
            this->goal = 9;
            while (this->ftab[this->goal]==0) {
                this->goal--;
            }
        }
    }

#ifndef METARESTORE
    if (oldgoal!=this->goal) {
        chunk_state_change(oldgoal,goal,allValidCopies,allValidCopies,rValidCopies,rValidCopies);
    }
#endif

    return STATUS_OK;
}

int CChunkObj::change_file(uint8_t prevgoal,uint8_t newgoal)
{
    if (this->fcount==0) {
#ifndef METARESTORE
        syslog(LOG_WARNING,"serious structure inconsistency: (chunkid:%016"PRIX64")",this->chunkid);
#else
        printf("serious structure inconsistency: (chunkid:%016"PRIX64")\n",this->chunkid);
#endif
        return ERROR_CHUNKLOST;	// ERROR_STRUCTURE
    }

#ifndef METARESTORE
    uint8_t oldgoal = this->goal;
#endif

    if (this->fcount==1) {
        this->goal = newgoal;
    } else {
        if (this->ftab==NULL) {
            this->ftab = (uint32_t*)malloc(sizeof(uint32_t)*10);
            passert(this->ftab);
            memset(this->ftab,0,sizeof(uint32_t)*10);
            this->ftab[this->goal]=this->fcount-1;
            this->ftab[newgoal]=1;
            if (newgoal > this->goal) {
                this->goal = newgoal;
            }
        } else {
            this->ftab[prevgoal]--;
            this->ftab[newgoal]++;
            this->goal = 9;
            while (this->ftab[this->goal]==0) {
                this->goal--;
            }
        }
    }

#ifndef METARESTORE
    if (oldgoal!=this->goal) {
        chunk_state_change(oldgoal,goal,allValidCopies,allValidCopies,rValidCopies,rValidCopies);
    }
#endif

    return STATUS_OK;
}

#ifndef METARESTORE
void CChunkObj::chunk_lost(void *ptr)
{
    slist *s, **sptr=&slisthead;
    while ((s=*sptr)) 
    {
        if (s->ptr==ptr) {
            if (s->valid==TDBUSY || s->valid==TDVALID)
            {
                chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies);
                allValidCopies--;
            }

            if (s->valid==BUSY || s->valid==VALID)
            {
                chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies-1);
                allValidCopies--;
                rValidCopies--;
            }

            bIncVer=1;
            *sptr = s->next;
            slist_free(s);
        } else {
            sptr = &(s->next);
        }
    }
}

void CChunkObj::emergency_increase_version() 
{
    uint32_t i=0;
    for (slist *s=slisthead ;s ; s=s->next)
    {
        if (s->valid!=INVALID && s->valid!=DEL)
        {
            if (s->valid==TDVALID || s->valid==TDBUSY) {
                s->valid = TDBUSY;
            } else {
                s->valid = BUSY;
            }

            s->version = version+1;
            matocsserv_send_setchunkversion(s->ptr,chunkid,version+1,version);
            i++;
        }
    }

    if (i>0) {	// should always be true !!!
        bInterrupted = 0;
        operation = SET_VERSION;
        version++;
    } else {
        matoclserv_chunk_status(chunkid,ERROR_CHUNKLOST);
    }

    fs_incversion(chunkid);
}

void CChunkObj::opr_status(uint8_t status, void *ptr)
{
    uint8_t valid=1,vs=0;
    for (slist *s=slisthead ; s ; s=s->next) 
    {
        if (s->ptr == ptr) {
            if (status!=0) {
                bInterrupted = 1;	// increase version after finish, just in case
                if (s->valid==TDBUSY || s->valid==TDVALID) {
                    chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies);
                    allValidCopies--;
                }

                if (s->valid==BUSY || s->valid==VALID) {
                    chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies-1);
                    allValidCopies--;
                    rValidCopies--;
                }

                s->valid=INVALID;
                s->version = 0;
            } else {
                if (s->valid==TDBUSY || s->valid==TDVALID) {
                    s->valid=TDVALID;
                } else {
                    s->valid=VALID;
                }
            }
        }

        if (s->valid==BUSY || s->valid==TDBUSY) {
            valid=0;
        }
        if (s->valid==VALID || s->valid==TDVALID) {
            vs++;
        }
    }

    if (valid) {
        if (vs>0) {
            if (bInterrupted) {
                emergency_increase_version();
            } else {
                matoclserv_chunk_status(chunkid,STATUS_OK);
                operation=NONE;
                bIncVer = 0;
            }
        } else {
            matoclserv_chunk_status(chunkid,ERROR_NOTDONE);
            operation=NONE;
        }
    }
}

void CChunkObj::has_svr_ver(void *ptr, uint32_t version)
{
    slist *s;
    for (s=this->slisthead ; s ; s=s->next) {
        if (s->ptr==ptr) {
            return;
        }
    }

    s = slist_malloc();
    s->ptr = ptr;
    if (this->version!=(version&0x7FFFFFFF)) {
        s->valid = INVALID;
        s->version = version&0x7FFFFFFF;
    } else {
        if (version&0x80000000) {
            s->valid=TDVALID;
            s->version = this->version;
            chunk_state_change(goal,goal,allValidCopies,allValidCopies+1,rValidCopies,rValidCopies);
            this->allValidCopies++;
        } else {
            s->valid=VALID;
            s->version = this->version;
            chunk_state_change(goal,goal,allValidCopies,allValidCopies+1,rValidCopies,rValidCopies+1);
            this->allValidCopies++;
            this->rValidCopies++;
        }
    }

    s->next = this->slisthead;
    this->slisthead = s;
}

void CChunkObj::damaged(void *ptr)
{
    slist *s;
    for (s=slisthead ; s ; s=s->next) {
        if (s->ptr==ptr) {
            if (s->valid==TDBUSY || s->valid==TDVALID) {
                chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies);
                allValidCopies--;
            }
            else if (s->valid==BUSY || s->valid==VALID) {
                chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies-1);
                allValidCopies--;
                rValidCopies--;
            }

            s->valid = INVALID;
            s->version = 0;
            bIncVer=1;
            return;
        }
    }//end for

    s = slist_malloc();
    s->ptr = ptr;
    s->valid = INVALID;
    s->version = 0;
    s->next = slisthead;
    bIncVer=1;
    slisthead = s;
}

void CChunkObj::delete_status(void *ptr)
{
    slist *s,**st;
    st = &slisthead;
    while (*st) {
        s = *st;
        if (s->ptr == ptr) {
            if (s->valid!=DEL) {
                if (s->valid==TDBUSY || s->valid==TDVALID) {
                    chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies);
                    allValidCopies--;
                }

                if (s->valid==BUSY || s->valid==VALID) {
                    chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies-1);
                    allValidCopies--;
                    rValidCopies--;
                }
                syslog(LOG_WARNING,"got unexpected delete status");
            }
            *st = s->next;
            slist_free(s);
        } else {
            st = &(s->next);
        }
    }//end while
}

void CChunkObj::disconnected(void *ptr)
{
    uint8_t valid= 1,vs = 0;
    slist *s,**st = &slisthead;
    while (*st)
    {
        s = *st;
        if (s->ptr == ptr)
        {
            if (s->valid==TDBUSY || s->valid==TDVALID)
            {
                chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies);
                allValidCopies--;
            }
            else if (s->valid==BUSY || s->valid==VALID)
            {
                chunk_state_change(goal,goal,allValidCopies,allValidCopies-1,rValidCopies,rValidCopies-1);
                allValidCopies--;
                rValidCopies--;
            }

            bIncVer=1;
            *st = s->next;
            slist_free(s);
        } else {
            st = &(s->next);
        }
    }//end while

    if (operation!=NONE) {
        for (s=slisthead ; s ; s=s->next) {
            if (s->valid==BUSY || s->valid==TDBUSY) {
                valid=0;
            }
            if (s->valid==VALID || s->valid==TDVALID) {
                vs++;
            }
        }

        if (valid) {
            if (vs>0) {
                emergency_increase_version();
            } else {
                matoclserv_chunk_status(chunkid, ERROR_NOTDONE);
                operation=NONE;
            }
        } else {
            bInterrupted = 1;
        }
    }//end if
}

#endif
