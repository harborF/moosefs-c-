#include "ServerCore.h"
#include "config.h"

static int s_lockfd = -1;

static inline pid_t mylock(int fd)
{
    struct flock fl;
    fl.l_start = 0;
    fl.l_len = 0;
    fl.l_pid = getpid();
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;

    for (;;) {
        if (fcntl(fd,F_SETLK,&fl)>=0) {	// lock set
            return 0;	// ok
        }
        if (errno!=EAGAIN) {	// error other than "already locked"
            return -1;	// error
        }
        if (fcntl(fd,F_GETLK,&fl)<0) {	// get lock owner
            return -1;	// error getting lock
        }
        if (fl.l_type!=F_UNLCK) {	// found lock
            return fl.l_pid;	// return lock owner
        }
    }

    return -1;	// pro forma
}

void CServerCore::wdunlock(void)
{
    if (s_lockfd>=0) {
        close(s_lockfd);
    }
}

int CServerCore::wdlock(uint8_t runmode,uint32_t timeout)
{
    s_lockfd = open("." STR(APPNAME) ".lock",O_WRONLY|O_CREAT,0666);
    if (s_lockfd<0) {
        mfs_errlog(LOG_ERR,"can't create lockfile in working directory");
        return -1;
    }

    pid_t ownerpid = mylock(s_lockfd);
    if (ownerpid<0) {
        mfs_errlog(LOG_ERR,"fcntl error");
        return -1;
    }

    if (ownerpid>0) {
        if (runmode==RM_TEST) {
            fprintf(stderr,STR(APPNAME) " pid: %ld\n",(long)ownerpid);
            return -1;
        }
        if (runmode==RM_START) {
            fprintf(stderr,"can't start: lockfile is already locked by another process\n");
            return -1;
        }
        if (runmode==RM_RELOAD) {
            if (kill(ownerpid,SIGHUP)<0) {
                mfs_errlog(LOG_WARNING,"can't send reload signal to lock owner");
                return -1;
            }
            fprintf(stderr,"reload signal has beed sent\n");
            return 0;
        }
        if (runmode==RM_KILL) {
            fprintf(stderr,"sending SIGKILL to lock owner (pid:%ld)\n",(long int)ownerpid);
            if (kill(ownerpid,SIGKILL)<0) {
                mfs_errlog(LOG_WARNING,"can't kill lock owner");
                return -1;
            }
        } else {
            fprintf(stderr,"sending SIGTERM to lock owner (pid:%ld)\n",(long int)ownerpid);
            if (kill(ownerpid,SIGTERM)<0) {
                mfs_errlog(LOG_WARNING,"can't kill lock owner");
                return -1;
            }
        }

        fprintf(stderr,"waiting for termination ... ");
        fflush(stderr);

        uint32_t l=0;
        pid_t newownerpid;
        do {
            newownerpid = mylock(s_lockfd);
            if (newownerpid<0) {
                mfs_errlog(LOG_ERR,"fcntl error");
                return -1;
            }

            if (newownerpid>0)
            {
                l++;
                if (l>=timeout) {
                    syslog(LOG_ERR,"about %"PRIu32" seconds passed and lockfile is still locked - giving up",l);
                    fprintf(stderr,"giving up\n");
                    return -1;
                }
                if (l%10==0) {
                    syslog(LOG_WARNING,"about %"PRIu32" seconds passed and lock still exists",l);
                    fprintf(stderr,"%"PRIu32"s ",l);
                    fflush(stderr);
                }

                if (newownerpid!=ownerpid) {
                    fprintf(stderr,"\nnew lock owner detected\n");
                    if (runmode==RM_KILL) {
                        fprintf(stderr,"sending SIGKILL to lock owner (pid:%ld) ... ",(long int)newownerpid);
                        fflush(stderr);
                        if (kill(newownerpid,SIGKILL)<0) {
                            mfs_errlog(LOG_WARNING,"can't kill lock owner");
                            return -1;
                        }
                    } else {
                        fprintf(stderr,"sending SIGTERM to lock owner (pid:%ld) ... ",(long int)newownerpid);
                        fflush(stderr);
                        if (kill(newownerpid,SIGTERM)<0) {
                            mfs_errlog(LOG_WARNING,"can't kill lock owner");
                            return -1;
                        }
                    }
                    ownerpid = newownerpid;
                }
            }
            sleep(1);
        } while (newownerpid!=0);
        fprintf(stderr,"terminated\n");
        return 0;
    }

    if (runmode==RM_START || runmode==RM_RESTART) {
        fprintf(stderr,"lockfile created and locked\n");
    } else if (runmode==RM_STOP || runmode==RM_KILL) {
        fprintf(stderr,"can't find process to terminate\n");
        return -1;
    } else if (runmode==RM_RELOAD) {
        fprintf(stderr,"can't find process to send reload signal\n");
        return -1;
    } else if (runmode==RM_TEST) {
        fprintf(stderr,STR(APPNAME) " is not running\n");
    }

    return 0;
}

int CServerCore::check_old_locks(uint8_t runmode,uint32_t timeout)
{
    char *lockfname = cfg_getstr("LOCK_FILE",RUN_PATH "/" STR(APPNAME) ".lock");
    s_lockfd=open(lockfname,O_RDWR);
    if (s_lockfd<0) {
        if (errno==ENOENT) {    // no old lock file
            free(lockfname);
            return 0;	// ok
        }
        mfs_arg_errlog(LOG_ERR,"open %s error",lockfname);
        free(lockfname);
        return -1;
    }

    if (lockf(s_lockfd, F_TLOCK,0)<0) {
        if (errno!=EAGAIN) {
            mfs_arg_errlog(LOG_ERR,"lock %s error",lockfname);
            free(lockfname);
            return -1;
        }
        if (runmode==RM_START) {
            mfs_syslog(LOG_ERR,"old lockfile is locked - can't start");
            free(lockfname);
            return -1;
        }
        if (runmode==RM_STOP || runmode==RM_KILL || runmode==RM_RESTART) {
            fprintf(stderr,"old lockfile found - trying to kill previous instance using data from old lockfile\n");
        } else if (runmode==RM_RELOAD) {
            fprintf(stderr,"old lockfile found - sending reload signal using data from old lockfile\n");
        }

        char str[13];
        uint32_t l=read(s_lockfd,str,13);
        if (l==0 || l>=13) {
            mfs_arg_syslog(LOG_ERR,"wrong pid in old lockfile %s",lockfname);
            free(lockfname);
            return -1;
        }

        str[l]=0;
        pid_t ptk = strtol(str,NULL,10);
        if (runmode==RM_RELOAD) {
            if (kill(ptk,SIGHUP)<0) {
                mfs_errlog(LOG_WARNING,"can't send reload signal");
                free(lockfname);
                return -1;
            }
            fprintf(stderr,"reload signal has beed sent\n");
            return 0;
        }

        if (runmode==RM_KILL) {
            fprintf(stderr,"sending SIGKILL to previous instance (pid:%ld)\n",(long int)ptk);
            if (kill(ptk,SIGKILL)<0) {
                mfs_errlog(LOG_WARNING,"can't kill previous process");
                free(lockfname);
                return -1;
            }
        } else {
            fprintf(stderr,"sending SIGTERM to previous instance (pid:%ld)\n",(long int)ptk);
            if (kill(ptk,SIGTERM)<0) {
                mfs_errlog(LOG_WARNING,"can't kill previous process");
                free(lockfname);
                return -1;
            }
        }

        l=0;
        fprintf(stderr,"waiting for termination ...\n");
        while (lockf(s_lockfd,F_TLOCK,0)<0) {
            if (errno!=EAGAIN) {
                mfs_arg_errlog(LOG_ERR,"lock %s error",lockfname);
                free(lockfname);
                return -1;
            }

            sleep(1);
            l++;

            if (l>=timeout) {
                mfs_arg_syslog(LOG_ERR,"about %"PRIu32" seconds passed and old lockfile is still locked - giving up",l);
                free(lockfname);
                return -1;
            }

            if (l%10==0) {
                mfs_arg_syslog(LOG_WARNING,"about %"PRIu32" seconds passed and old lockfile is still locked",l);
            }
        }
        fprintf(stderr,"terminated\n");
    } else {
        fprintf(stderr,"found unlocked old lockfile\n");
        if (runmode==RM_RELOAD) {
            fprintf(stderr,"can't obtain process id using old lockfile\n");
            return 0;
        }
    }

    fprintf(stderr,"removing old lockfile\n");
    close(s_lockfd);
    unlink(lockfname);
    free(lockfname);

    return 0;
}

void CServerCore::remove_old_wdlock(void)
{
    unlink(".lock_" STR(APPNAME));
}
