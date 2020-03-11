#include "config.h"

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/resource.h>

#include "charts.h"
#include "ServerCore.h"

#include "FrontConn.h"
#include "MasterConn.h"
#include "HddSpaceMgr.h"
#include "Replicator.h"

#define CHARTS_FILENAME "csstats.mfs"

#define CHARTS_UCPU 0
#define CHARTS_SCPU 1
#define CHARTS_MASTERIN 2
#define CHARTS_MASTEROUT 3
#define CHARTS_CSCONNIN 4
#define CHARTS_CSCONNOUT 5
#define CHARTS_CSSERVIN 6
#define CHARTS_CSSERVOUT 7
#define CHARTS_BYTESR 8
#define CHARTS_BYTESW 9
#define CHARTS_LLOPR 10
#define CHARTS_LLOPW 11
#define CHARTS_DATABYTESR 12
#define CHARTS_DATABYTESW 13
#define CHARTS_DATALLOPR 14
#define CHARTS_DATALLOPW 15
#define CHARTS_HLOPR 16
#define CHARTS_HLOPW 17
#define CHARTS_RTIME 18
#define CHARTS_WTIME 19
#define CHARTS_REPL 20
#define CHARTS_CREATE 21
#define CHARTS_DELETE 22
#define CHARTS_VERSION 23
#define CHARTS_DUPLICATE 24
#define CHARTS_TRUNCATE 25
#define CHARTS_DUPTRUNC 26
#define CHARTS_TEST 27
#define CHARTS_CHUNKIOJOBS 28
#define CHARTS_CHUNKOPJOBS 29

#define CHARTS 30

/* name , join mode , percent , scale , multiplier , divisor */
#define STATDEFS { \
	{(char*)"ucpu"         ,CHARTS_MODE_ADD,1,CHARTS_SCALE_MICRO, 100,60}, \
	{(char*)"scpu"         ,CHARTS_MODE_ADD,1,CHARTS_SCALE_MICRO, 100,60}, \
	{(char*)"masterin"     ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{(char*)"masterout"    ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{(char*)"csconnin"     ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{(char*)"csconnout"    ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{(char*)"csservin"     ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{(char*)"csservout"    ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{(char*)"bytesr"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,1000,60}, \
	{(char*)"bytesw"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,1000,60}, \
	{(char*)"llopr"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"llopw"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"databytesr"   ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,1000,60}, \
	{(char*)"databytesw"   ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,1000,60}, \
	{(char*)"datallopr"    ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"datallopw"    ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"hlopr"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"hlopw"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"rtime"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MICRO,   1,60}, \
	{(char*)"wtime"        ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MICRO,   1,60}, \
	{(char*)"repl"         ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"create"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"delete"       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"version"      ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"duplicate"    ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"truncate"     ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"duptrunc"     ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"test"         ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"chunkiojobs"  ,CHARTS_MODE_MAX,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{(char*)"chunkopjobs"  ,CHARTS_MODE_MAX,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{NULL           ,0              ,0,0                 ,   0, 0}  \
};

#define CALCDEFS { \
	CHARTS_DEFS_END \
};

/* c1_def , c2_def , c3_def , join mode , percent , scale , multiplier , divisor */
#define ESTATDEFS { \
	{CHARTS_DIRECT(CHARTS_UCPU)        ,CHARTS_DIRECT(CHARTS_SCPU)        ,CHARTS_NONE                       ,CHARTS_MODE_ADD,1,CHARTS_SCALE_MICRO, 100,60}, \
	{CHARTS_DIRECT(CHARTS_CSSERVIN)    ,CHARTS_DIRECT(CHARTS_CSCONNIN)    ,CHARTS_NONE                       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{CHARTS_DIRECT(CHARTS_CSSERVOUT)   ,CHARTS_DIRECT(CHARTS_CSCONNOUT)   ,CHARTS_NONE                       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,8000,60}, \
	{CHARTS_DIRECT(CHARTS_BYTESR)      ,CHARTS_DIRECT(CHARTS_DATABYTESR)  ,CHARTS_NONE                       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,1000,60}, \
	{CHARTS_DIRECT(CHARTS_BYTESW)      ,CHARTS_DIRECT(CHARTS_DATABYTESW)  ,CHARTS_NONE                       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_MILI ,1000,60}, \
	{CHARTS_DIRECT(CHARTS_LLOPR)       ,CHARTS_DIRECT(CHARTS_DATALLOPR)   ,CHARTS_NONE                       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{CHARTS_DIRECT(CHARTS_LLOPW)       ,CHARTS_DIRECT(CHARTS_DATALLOPW)   ,CHARTS_NONE                       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{CHARTS_DIRECT(CHARTS_CHUNKOPJOBS) ,CHARTS_DIRECT(CHARTS_CHUNKIOJOBS) ,CHARTS_NONE                       ,CHARTS_MODE_ADD,0,CHARTS_SCALE_NONE ,   1, 1}, \
	{CHARTS_NONE                       ,CHARTS_NONE                       ,CHARTS_NONE                       ,0              ,0,0                 ,   0, 0}  \
};

static const uint32_t calcdefs[]=CALCDEFS
static const statdef statdefs[]=STATDEFS
static const estatdef estatdefs[]=ESTATDEFS

static struct itimerval it_set;

void chartsdata_refresh(void) {
	uint64_t data[CHARTS];
	uint64_t bin,bout;
	uint32_t i,opr,opw,dbr,dbw,dopr,dopw,repl;
	uint32_t op_cr,op_de,op_ve,op_du,op_tr,op_dt,op_te;
	uint32_t csservjobs,masterjobs;
	struct itimerval uc,pc;
	uint32_t ucusec,pcusec;
//	struct rusage sru,chru;
//	long ru_nswap,ru_minflt,ru_majflt,ru_inblock,ru_oublock,ru_nvcsw,ru_nivcsw;
//	static long l_nswap=0,l_minflt=0,l_majflt=0,l_inblock=0,l_oublock=0,l_nvcsw=0,l_nivcsw=0;

	for (i=0 ; i<CHARTS ; i++) {
		data[i]=0;
	}

//	getrusage(RUSAGE_SELF,&sru);
//	getrusage(RUSAGE_CHILDREN,&chru);

//	ru_minflt = sru.ru_minflt + chru.ru_minflt;
//	ru_majflt = sru.ru_majflt + chru.ru_majflt;
//	ru_nswap = sru.ru_nswap + chru.ru_nswap;
//	ru_inblock = sru.ru_inblock + chru.ru_inblock;
//	ru_oublock = sru.ru_oublock + chru.ru_oublock;
//	ru_nvcsw = sru.ru_nvcsw + chru.ru_nvcsw;
//	ru_nivcsw = sru.ru_nivcsw + chru.ru_nivcsw;
//	data[CHARTS_MINFLT] = ru_minflt - l_minflt;
//	data[CHARTS_MAJFLT] = ru_majflt - l_majflt;
//	data[CHARTS_NSWAP] = ru_nswap - l_nswap;
//	data[CHARTS_INBLOCK] = ru_inblock - l_inblock;
//	data[CHARTS_OUBLOCK] = ru_oublock - l_oublock;
//	data[CHARTS_NVCSW] = ru_nvcsw - l_nvcsw;
//	data[CHARTS_NIVCSW] = ru_nivcsw - l_nivcsw;
//	l_minflt = ru_minflt;
//	l_majflt = ru_majflt;
//	l_nswap = ru_nswap;
//	l_inblock = ru_inblock;
//	l_oublock = ru_oublock;
//	l_nvcsw = ru_nvcsw;
//	l_nivcsw = ru_nivcsw;

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

	ucusec = uc.it_value.tv_sec*1000000+uc.it_value.tv_usec;
	pcusec = pc.it_value.tv_sec*1000000+pc.it_value.tv_usec;

	if (pcusec>ucusec) {
		pcusec-=ucusec;
	} else {
		pcusec=0;
	}
	data[CHARTS_UCPU] = ucusec;
	data[CHARTS_SCPU] = pcusec;

	masterconn_stats(&bin,&bout,&masterjobs);
	data[CHARTS_MASTERIN]=bin;
	data[CHARTS_MASTEROUT]=bout;
	data[CHARTS_CHUNKOPJOBS]=masterjobs;
//	cstocsconn_stats(&bin,&bout);
//	data[CHARTS_CSCONNIN]=bin;
//	data[CHARTS_CSCONNOUT]=bout;
	data[CHARTS_CSCONNIN]=0;
	data[CHARTS_CSCONNOUT]=0;
	csserv_stats(&bin,&bout,&opr,&opw,&csservjobs);
	data[CHARTS_CSSERVIN]=bin;
	data[CHARTS_CSSERVOUT]=bout;
	data[CHARTS_CHUNKIOJOBS]=csservjobs;
	data[CHARTS_HLOPR]=opr;
	data[CHARTS_HLOPW]=opw;
	hdd_stats(&bin,&bout,&opr,&opw,&dbr,&dbw,&dopr,&dopw,data+CHARTS_RTIME,data+CHARTS_WTIME);
	data[CHARTS_BYTESR]=bin;
	data[CHARTS_BYTESW]=bout;
	data[CHARTS_LLOPR]=opr;
	data[CHARTS_LLOPW]=opw;
	data[CHARTS_DATABYTESR]=dbr;
	data[CHARTS_DATABYTESW]=dbw;
	data[CHARTS_DATALLOPR]=dopr;
	data[CHARTS_DATALLOPW]=dopw;
	replicator_stats(&repl);
	data[CHARTS_REPL]=repl;
	hdd_op_stats(&op_cr,&op_de,&op_ve,&op_du,&op_tr,&op_dt,&op_te);
	data[CHARTS_CREATE]=op_cr;
	data[CHARTS_DELETE]=op_de;
	data[CHARTS_VERSION]=op_ve;
	data[CHARTS_DUPLICATE]=op_du;
	data[CHARTS_TRUNCATE]=op_tr;
	data[CHARTS_DUPTRUNC]=op_dt;
	data[CHARTS_TEST]=op_te;

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
	struct itimerval uc,pc;

	it_set.it_interval.tv_sec = 0;
	it_set.it_interval.tv_usec = 0;
	it_set.it_value.tv_sec = 999;
	it_set.it_value.tv_usec = 999999;
	setitimer(ITIMER_VIRTUAL,&it_set,&uc);             // user time
	setitimer(ITIMER_PROF,&it_set,&pc);                // user time + system time

	CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,60,0,chartsdata_refresh);
	CServerCore::getInstance()->time_register(TIMEMODE_RUN_LATE,3600,0,chartsdata_store);
	CServerCore::getInstance()->destruct_register(chartsdata_term);

	return charts_init(calcdefs,statdefs,estatdefs,CHARTS_FILENAME);
}
