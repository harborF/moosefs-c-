#include "config.h"

#if defined(HAVE_MLOCKALL)
#  if defined(HAVE_SYS_MMAN_H)
#    include <sys/mman.h>
#  endif
#  if defined(HAVE_SYS_RESOURCE_H)
#    include <sys/resource.h>
#  endif
#  if defined(RLIMIT_MEMLOCK) && defined(MCL_CURRENT) && defined(MCL_FUTURE)
#    define MFS_USE_MEMLOCK 1
#  endif
#endif

#include <sys/resource.h>
#include <grp.h>
#include <pwd.h>

#include "crc.h"
#include "ServerInit.h"
#include "ServerCore.h"

int initialize(void) {
	int ok = 1;
	for (uint32_t i=0 ; (long int)(RunTab[i].fn)!=0 && ok ; i++) {
		CServerCore::s_now = time(NULL);
		if (RunTab[i].fn()<0) {
			mfs_arg_syslog(LOG_ERR,"init: %s failed !!!",RunTab[i].name);
			ok=0;
		}
	}
	return ok;
}

int initialize_late(void) {
	int ok = 1;
	for (uint32_t i=0 ; (long int)(LateRunTab[i].fn)!=0 && ok ; i++) {
		CServerCore::s_now = time(NULL);
		if (LateRunTab[i].fn()<0) {
			mfs_arg_syslog(LOG_ERR,"init: %s failed !!!",RunTab[i].name);
			ok=0;
		}
	}
	CServerCore::s_now = time(NULL);

	return ok;
}

void changeugid(void) {
	char pwdgrpbuff[16384];
	struct passwd pwd,*pw;
	struct group grp,*gr;
	char *wuser, *wgroup;
	uid_t wrk_uid;
	gid_t wrk_gid;

	if (geteuid()==0) {
		wuser = cfg_getstr("WORKING_USER",DEFAULT_USER);
		wgroup = cfg_getstr("WORKING_GROUP",DEFAULT_GROUP);

		int gidok = 0;
		wrk_gid = -1;
		if (wgroup[0]=='#') {
			wrk_gid = strtol(wgroup+1,NULL,10);
			gidok = 1;
		} else if (wgroup[0]) {
			getgrnam_r(wgroup,&grp,pwdgrpbuff,16384,&gr);
			if (gr==NULL) {
				mfs_arg_syslog(LOG_WARNING,"%s: no such group !!!",wgroup);
				exit(1);
			} else {
				wrk_gid = gr->gr_gid;
				gidok = 1;
			}
		}

		if (wuser[0]=='#') {
			wrk_uid = strtol(wuser+1,NULL,10);
			if (gidok==0) {
				getpwuid_r(wrk_uid,&pwd,pwdgrpbuff,16384,&pw);
				if (pw==NULL) {
					mfs_arg_syslog(LOG_ERR,"%s: no such user id - can't obtain group id",wuser+1);
					exit(1);
				}
				wrk_gid = pw->pw_gid;
			}
		} else {
			getpwnam_r(wuser,&pwd,pwdgrpbuff,16384,&pw);
			if (pw==NULL) {
				mfs_arg_syslog(LOG_ERR,"%s: no such user !!!",wuser);
				exit(1);
			}
			wrk_uid = pw->pw_uid;
			if (gidok==0) {
				wrk_gid = pw->pw_gid;
			}
		}
		free(wuser);
		free(wgroup);

		if (setgid(wrk_gid)<0) {
			mfs_arg_errlog(LOG_ERR,"can't set gid to %d",(int)wrk_gid);
			exit(1);
		} else {
			syslog(LOG_NOTICE,"set gid to %d",(int)wrk_gid);
		}
		if (setuid(wrk_uid)<0) {
			mfs_arg_errlog(LOG_ERR,"can't set uid to %d",(int)wrk_uid);
			exit(1);
		} else {
			syslog(LOG_NOTICE,"set uid to %d",(int)wrk_uid);
		}
	}
}

void makedaemon() {
	uint8_t pipebuff[1000];
	ssize_t r;
	size_t happy;
	int piped[2];

	fflush(stdout);
	fflush(stderr);
	if (pipe(piped)<0) {
		fprintf(stderr,"pipe error\n");
		exit(1);
	}

	int f = fork();
	if (f<0) {
		syslog(LOG_ERR,"first fork error: %s",strerr(errno));
		exit(1);
	}
	if (f>0) {
		wait(&f);	// just get child status - prevents child from being zombie during initialization stage
		if (f) {
			fprintf(stderr,"Child status: %d\n",f);
			exit(1);
		}
		close(piped[1]);
//		printf("Starting daemon ...\n");
		while ((r=read(piped[0],pipebuff,1000))) {
			if (r>0) {
				if (pipebuff[r-1]==0) {	// zero as a last char in the pipe means error
					if (r>1) {
						happy = fwrite(pipebuff,1,r-1,stderr);
						(void)happy;
					}
					exit(1);
				}
				happy = fwrite(pipebuff,1,r,stderr);
				(void)happy;
			} else {
				fprintf(stderr,"Error reading pipe: %s\n",strerr(errno));
				exit(1);
			}
		}
		exit(0);
	}

	setsid();
	setpgid(0,getpid());
	f = fork();
	if (f<0) {
		syslog(LOG_ERR,"second fork error: %s",strerr(errno));
		if (write(piped[1],"fork error\n",11)!=11) {
			syslog(LOG_ERR,"pipe write error: %s",strerr(errno));
		}
		close(piped[1]);
		exit(1);
	}
	if (f>0) {
		exit(0);
	}
	CServerCore::set_signal_handlers(1);

	close(STDIN_FILENO);
	sassert(open("/dev/null", O_RDWR, 0)==STDIN_FILENO);
	close(STDOUT_FILENO);
	sassert(dup(STDIN_FILENO)==STDOUT_FILENO);
	close(STDERR_FILENO);
	sassert(dup(piped[1])==STDERR_FILENO);
	close(piped[1]);
//	setvbuf(stderr,(char *)NULL,_IOLBF,0);
}

void close_msg_channel() {
	fflush(stderr);
	close(STDERR_FILENO);
	sassert(open("/dev/null", O_RDWR, 0)==STDERR_FILENO);
}

void createpath(const char *filename)
{
	char pathbuff[1024];
	const char *src = filename;
	char *dst = pathbuff;
	if (*src=='/') *dst++=*src++;

	while (*src)
    {
		while (*src!='/' && *src) {
			*dst++=*src++;
		}

		if (*src=='/')
        {
			*dst='\0';
			if (mkdir(pathbuff,(mode_t)0777)<0) {
				if (errno!=EEXIST) {
					mfs_arg_errlog(LOG_NOTICE,"creating directory %s",pathbuff);
				}
			} else {
				mfs_arg_syslog(LOG_NOTICE,"directory %s has been created",pathbuff);
			}

			*dst++=*src++;
		}
	}
}

void usage(const char *appname) {
	printf(
"usage: %s [-vdu] [-t locktimeout] [-c cfgfile] [start|stop|restart|reload|test]\n"
"\n"
"-v : print version number and exit\n"
"-d : run in foreground\n"
"-u : log undefined config variables\n"
"-t locktimeout : how long wait for lockfile\n"
"-c cfgfile : use given config file\n"
	,appname);
	exit(1);
}

int main(int argc,char **argv)
{
	strerr_init();
	mycrc32_init();

	int fd;
	uint8_t movewarning = 0;
	char *cfgfile=strdup(ETC_PATH "/mfs/" STR(APPNAME) ".cfg");
	passert(cfgfile);
	if ((fd = open(cfgfile,O_RDONLY))<0 && errno==ENOENT) {
		free(cfgfile);
		cfgfile=strdup(ETC_PATH "/" STR(APPNAME) ".cfg");
		passert(cfgfile);
		if ((fd = open(cfgfile,O_RDONLY))>=0) {
			movewarning = 1;
		}
	}
	if (fd>=0) {
		close(fd);
	}

	int ch;
	uint32_t locktimeout = 1800;
	int rundaemon = 1,logundefined = 0;
	uint8_t runmode = RM_RESTART;
	int lockmemory = 0;
	char *appname = argv[0];

	while ((ch = getopt(argc, argv, "uvdfsc:t:h?")) != -1) {
		switch(ch) {
			case 'v':
				printf("version: %u.%u.%u\n",VERSMAJ,VERSMID,VERSMIN);
				return 0;
			case 'd':
				rundaemon=0;
				break;
			case 'f':
				runmode=RM_START;
				break;
			case 's':
				runmode=RM_STOP;
				break;
			case 't':
				locktimeout=strtoul(optarg,NULL,10);
				break;
			case 'c':
				free(cfgfile);
				cfgfile = strdup(optarg);
				passert(cfgfile);
				movewarning = 0;
				break;
			case 'u':
				logundefined=1;
				break;
			default:
				usage(appname);
				return 1;
		}
	}

	argc -= optind;
	argv += optind;

	if (argc==1) {
		if (strcasecmp(argv[0],"start")==0) {
			runmode = RM_START;
		} else if (strcasecmp(argv[0],"stop")==0) {
			runmode = RM_STOP;
		} else if (strcasecmp(argv[0],"restart")==0) {
			runmode = RM_RESTART;
		} else if (strcasecmp(argv[0],"reload")==0) {
			runmode = RM_RELOAD;
		} else if (strcasecmp(argv[0],"test")==0) {
			runmode = RM_TEST;
		} else if (strcasecmp(argv[0],"kill")==0) {
			runmode = RM_KILL;
		} else {
			usage(appname);
			return 1;
		}
	} else if (argc!=0) {
		usage(appname);
		return 1;
	}

	if (movewarning) {
		mfs_syslog(LOG_WARNING,"default sysconf path has changed - please move " STR(APPNAME) ".cfg from "ETC_PATH"/ to "ETC_PATH"/mfs/");
	}

	if ((runmode==RM_START || runmode==RM_RESTART) && rundaemon) {
		makedaemon();
	} else {
		if (runmode==RM_START || runmode==RM_RESTART) {
			CServerCore::set_signal_handlers(0);
		}
	}

	if (cfg_load(cfgfile,logundefined)==0) {
		fprintf(stderr,"can't load config file: %s - using defaults\n",cfgfile);
	}
	free(cfgfile);

    char *logappname = cfg_getstr("SYSLOG_IDENT",STR(APPNAME));
	if (rundaemon) {
		if (logappname[0]) {
			openlog(logappname, LOG_PID | LOG_NDELAY , LOG_DAEMON);
		} else {
			openlog(STR(APPNAME), LOG_PID | LOG_NDELAY , LOG_DAEMON);
		}
	} else {
#if defined(LOG_PERROR)
		if (logappname[0]) {
			openlog(logappname, LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_USER);
		} else {
			openlog(STR(APPNAME), LOG_PID | LOG_NDELAY | LOG_PERROR, LOG_USER);
		}
#else
		if (logappname[0]) {
			openlog(logappname, LOG_PID | LOG_NDELAY, LOG_USER);
		} else {
			openlog(STR(APPNAME), LOG_PID | LOG_NDELAY, LOG_USER);
		}
#endif
	}

    int32_t nicelevel;
    struct rlimit rls;
    if (runmode==RM_START || runmode==RM_RESTART) {
		rls.rlim_cur = MFSMAXFILES;
		rls.rlim_max = MFSMAXFILES;
		if (setrlimit(RLIMIT_NOFILE,&rls)<0) {
			syslog(LOG_NOTICE,"can't change open files limit to %u",MFSMAXFILES);
		}

		lockmemory = cfg_getnum("LOCK_MEMORY",0);
#ifdef MFS_USE_MEMLOCK
		if (lockmemory) {
			rls.rlim_cur = RLIM_INFINITY;
			rls.rlim_max = RLIM_INFINITY;
			setrlimit(RLIMIT_MEMLOCK,&rls);
		}
#endif
		nicelevel = cfg_getint32("NICE_LEVEL",-19);
		setpriority(PRIO_PROCESS,getpid(),nicelevel);
	}

	changeugid();

	char *wrkdir = cfg_getstr("DATA_PATH",DATA_PATH);
	if (runmode==RM_START || runmode==RM_RESTART) {
		fprintf(stderr,"working directory: %s\n",wrkdir);
	}

	if (chdir(wrkdir)<0) {
		mfs_arg_syslog(LOG_ERR,"can't set working directory to %s",wrkdir);
		if (rundaemon) {
			fputc(0,stderr);
			close_msg_channel();
		}
		closelog();
		free(logappname);
		return 1;
	}
	free(wrkdir);

	umask(cfg_getuint32("FILE_UMASK",027)&077);

	/* for upgrading from previous versions of MFS */
	if (CServerCore::check_old_locks(runmode,locktimeout)<0) {
		if (rundaemon) {
			fputc(0,stderr);
			close_msg_channel();
		}
		closelog();
		free(logappname);
		CServerCore::wdunlock();
		return 1;
	}

	if (CServerCore::wdlock(runmode,locktimeout)<0) {
		if (rundaemon) {
			fputc(0,stderr);
			close_msg_channel();
		}
		closelog();
		free(logappname);
		CServerCore::wdunlock();
		return 1;
	}
	CServerCore::remove_old_wdlock();

	if (runmode==RM_STOP || runmode==RM_KILL || runmode==RM_RELOAD || runmode==RM_TEST) {
		if (rundaemon) {
			close_msg_channel();
		}
		closelog();
		free(logappname);
		CServerCore::wdunlock();
		return 0;
	}

#ifdef MFS_USE_MEMLOCK
	if (lockmemory) {
		if (getrlimit(RLIMIT_MEMLOCK,&rls)<0) {
			mfs_errlog(LOG_WARNING,"error getting memory lock limits");
		} else {
			if (rls.rlim_cur!=RLIM_INFINITY && rls.rlim_max==RLIM_INFINITY) {
				rls.rlim_cur = RLIM_INFINITY;
				rls.rlim_max = RLIM_INFINITY;
				if (setrlimit(RLIMIT_MEMLOCK,&rls)<0) {
					mfs_errlog(LOG_WARNING,"error setting memory lock limit to unlimited");
				}
			}
			if (getrlimit(RLIMIT_MEMLOCK,&rls)<0) {
				mfs_errlog(LOG_WARNING,"error getting memory lock limits");
			} else {
				if (rls.rlim_cur!=RLIM_INFINITY) {
					mfs_errlog(LOG_WARNING,"can't set memory lock limit to unlimited");
				} else {
					if (mlockall(MCL_CURRENT|MCL_FUTURE)<0) {
						mfs_errlog(LOG_WARNING,"memory lock error");
					} else {
						mfs_syslog(LOG_NOTICE,"process memory was successfully locked in RAM");
					}
			}	}
		}
	}
#else
	if (lockmemory) {
		mfs_syslog(LOG_WARNING,"memory lock not supported !!!");
	}
#endif
	fprintf(stderr,"initializing %s modules ...\n",logappname);

	if (initialize()) {
		if (getrlimit(RLIMIT_NOFILE,&rls)==0) {
			syslog(LOG_NOTICE,"open files limit: %lu",(unsigned long)(rls.rlim_cur));
		}
		fprintf(stderr,"%s daemon initialized properly\n",logappname);
		if (rundaemon) {
			close_msg_channel();
		}
		if (initialize_late()) {
			CServerCore::getInstance()->mainloop();
			ch=0;
		} else {
			ch=1;
		}
	} else {
		fprintf(stderr,"error occured during initialization - exiting\n");
		if (rundaemon) {
			fputc(0,stderr);
			close_msg_channel();
		}
		ch=1;
	}

	CServerCore::getInstance()->destruct();
	CServerCore::getInstance()->free_all_entries();
	CServerCore::signal_cleanup();

	cfg_term();
	strerr_term();
	closelog();
	free(logappname);
	CServerCore::wdunlock();

	return ch;
}
