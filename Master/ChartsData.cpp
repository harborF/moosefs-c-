#include "config.h"

#if defined(HAVE_GETRUSAGE) && defined(HAVE_STRUCT_RUSAGE_RU_MAXRSS)
#  include <sys/types.h>
#  ifdef HAVE_SYS_RESOURCE_H
#    include <sys/resource.h>
#  endif
#  ifdef HAVE_SYS_RUSAGE_H
#    include <sys/rusage.h>
#  endif
#  ifndef RUSAGE_SELF
#    define RUSAGE_SELF 0
#  endif
#  define MEMORY_USAGE 1
#endif

#if defined(HAVE_SETITIMER)
#  include <sys/time.h>
#  ifndef ITIMER_REAL
#    define ITIMER_REAL 0
#  endif
#  ifndef ITIMER_VIRTUAL
#    define ITIMER_VIRTUAL 1
#  endif
#  ifndef ITIMER_PROF
#    define ITIMER_PROF 2
#  endif
#  define CPU_USAGE 1
#endif

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>


#include "charts.h"
#include "ServerCore.h"

#include "FileSysMgr.h"
#include "ClientCtrl.h"

#define CHARTS_FILENAME "stats.mfs"

#define CHARTS_UCPU 0
#define CHARTS_SCPU 1
#define CHARTS_DELCHUNK 2
#define CHARTS_REPLCHUNK 3
#define CHARTS_STATFS 4
#define CHARTS_GETATTR 5
#define CHARTS_SETATTR 6
#define CHARTS_LOOKUP 7
#define CHARTS_MKDIR 8
#define CHARTS_RMDIR 9
#define CHARTS_SYMLINK 10
#define CHARTS_READLINK 11
#define CHARTS_MKNOD 12
#define CHARTS_UNLINK 13
#define CHARTS_RENAME 14
#define CHARTS_LINK 15
#define CHARTS_READDIR 16
#define CHARTS_OPEN 17
#define CHARTS_READ 18
#define CHARTS_WRITE 19
#define CHARTS_MEMORY 20
#define CHARTS_PACKETSRCVD 21
#define CHARTS_PACKETSSENT 22
#define CHARTS_BYTESRCVD 23
#define CHARTS_BYTESSENT 24

#define CHARTS 25

/* name , join mode , percent , scale , multiplier , divisor */
#define STATDEFS { \
	{(char*)"ucpu"         ,CHARTS_MODE_ADD,1,CHARTS_SCALE_MICRO, 100,60}, \
	{(char*)"scpu"         ,CHARTS_MODE_ADD,1,CHARTS_SCALE_MICRO, 100,60}, \
	{(char*)"delete"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"replicate"    ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"statfs"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"getattr"      ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"setattr"      ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"lookup"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"mkdir"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"rmdir"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"symlink"      ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"readlink"     ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"mknod"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"unlink"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"rename"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"link"         ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"readdir"      ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"open"         ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"read"         ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"write"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"memory"       ,CHARTS_MODE_MAX,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"prcvd"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,1000,60}, \
	{(char*)"psent"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,1000,60}, \
	{(char*)"brcvd"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{(char*)"bsent"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{NULL           ,0              ,0,0                 ,   0, 0}  \
};

#define CALCDEFS { \
	CHARTS_DEFS_END \
};

/* c1_def , c2_def , c3_def , join mode , percent , scale , multiplier , divisor */
#define ESTATDEFS { \
	{CHARTS_DIRECT(CHARTS_UCPU)        ,CHARTS_DIRECT(CHARTS_SCPU)        ,CHARTS_NONE                       ,CHARTS_MODE_ADD,1,CHARTS_SCALE_MICRO, 100,60}, \
	{CHARTS_NONE                       ,CHARTS_NONE                       ,CHARTS_NONE                       ,0              ,0,0                 ,   0, 0}  \
};

static const uint32_t calcdefs[]=CALCDEFS
static const statdef statdefs[]=STATDEFS
static const estatdef estatdefs[]=ESTATDEFS

#ifdef CPU_USAGE
static struct itimerval it_set;
#endif
#ifdef MEMORY_USAGE
static uint64_t memusage;
#endif

uint64_t chartsdata_memusage(void) {
	return memusage;
}

void chartsdata_refresh(void) {
	uint64_t data[CHARTS];
	uint32_t fsdata[16];
	uint32_t i,del,repl; //,bin,bout,opr,opw,dbr,dbw,dopr,dopw,repl;
#ifdef CPU_USAGE
	struct itimerval uc,pc;
	uint32_t ucusec,pcusec;
#endif
#ifdef MEMORY_USAGE
	struct rusage ru;
#endif

	for (i=0 ; i<CHARTS ; i++) {
		data[i]=CHARTS_NODATA;
	}

#ifdef CPU_USAGE
// CPU usage
	setitimer(ITIMER_VIRTUAL,&it_set,&uc);             // user time
	setitimer(ITIMER_PROF,&it_set,&pc);                // user time + system time

	if (uc.it_value.tv_sec<=999) {	// on fucken linux timers can go backward !!!
		uc.it_value.tv_sec = 999-uc.it_value.tv_sec;
		uc.it_value.tv_usec = 999999-uc.it_value.tv_usec;
	} else {
		uc.it_value.tv_sec = 0;
		uc.it_value.tv_usec = 0;
	}
	if (pc.it_value.tv_sec<=999) {	// as abowe - who the hell has invented this stupid os !!!
		pc.it_value.tv_sec = 999-pc.it_value.tv_sec;
		pc.it_value.tv_usec = 999999-pc.it_value.tv_usec;
	} else {
		pc.it_value.tv_sec = 0;
		uc.it_value.tv_usec = 0;
	}

	ucusec = uc.it_value.tv_sec*1000000U+uc.it_value.tv_usec;
	pcusec = pc.it_value.tv_sec*1000000U+pc.it_value.tv_usec;

	if (pcusec>ucusec) {
		pcusec-=ucusec;
	} else {
		pcusec=0;
	}
	data[CHARTS_UCPU] = ucusec;
	data[CHARTS_SCPU] = pcusec;
#endif

// memory usage
#ifdef MEMORY_USAGE
	getrusage(RUSAGE_SELF,&ru);
#  ifdef __APPLE__
	memusage = ru.ru_maxrss;
#  else
	memusage = ru.ru_maxrss * UINT64_C(1024);
#  endif
#  ifdef __linux__
	if (memusage==0) {
		int fd = open("/proc/self/statm",O_RDONLY);
		char statbuff[1000];
		int l;
		if (fd>=0) {
			l = read(fd,statbuff,1000);
			if (l<1000 && l>0) {
				statbuff[l]=0;
				memusage = strtoul(statbuff,NULL,10)*getpagesize();
			}
			close(fd);
		}
	}
#  endif
	if (memusage>0) {
		data[CHARTS_MEMORY] = memusage;
	}
#endif

	CFileSysMgr::chunk_stats(&del,&repl);
	data[CHARTS_DELCHUNK]=del;
	data[CHARTS_REPLCHUNK]=repl;
	CFileSysMgr::get_stats(fsdata);
	for (i=0 ; i<16 ; i++) {
		data[CHARTS_STATFS+i]=fsdata[i];
	}
	matoclserv_stats(data+CHARTS_PACKETSRCVD);

	charts_add(data, CServerCore::get_time()-60);
}

void chartsdata_term(void) {
	chartsdata_refresh();
	charts_store();
	charts_term();
}

void chartsdata_store(void) {
	charts_store();
}

int chartsdata_init (void) {
#ifdef CPU_USAGE
	struct itimerval uc,pc;
#endif
#ifdef MEMORY_USAGE
	struct rusage ru;
#endif

#ifdef CPU_USAGE
	it_set.it_interval.tv_sec = 0;
	it_set.it_interval.tv_usec = 0;
	it_set.it_value.tv_sec = 999;
	it_set.it_value.tv_usec = 999999;
	setitimer(ITIMER_VIRTUAL,&it_set,&uc);             // user time
	setitimer(ITIMER_PROF,&it_set,&pc);                // user time + system time
#endif

#ifdef MEMORY_USAGE
	getrusage(RUSAGE_SELF,&ru);
#  ifdef __APPLE__
	memusage = ru.ru_maxrss;
#  else
	memusage = ru.ru_maxrss * 1024;
#  endif
#endif

    CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,60,0,chartsdata_refresh);
	CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,3600,0,chartsdata_store);
	CServerCore::getInstance()->destruct_register(chartsdata_term);

	return charts_init(calcdefs,statdefs,estatdefs,CHARTS_FILENAME);
}
