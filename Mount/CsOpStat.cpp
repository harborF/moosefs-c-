#include "config.h"

#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>

#define CSDB_HASHSIZE 256
#define CSDB_HASH(ip,port) (((ip)*0x7b348943+(port))%(CSDB_HASHSIZE))

typedef struct _csdbentry {
	uint32_t ip;
	uint16_t port;
	uint32_t readopcnt;
	uint32_t writeopcnt;
	struct _csdbentry *next;
} STCsOpEntry;

static STCsOpEntry *s_OpCntHash[CSDB_HASHSIZE];
static pthread_mutex_t *s_OpLock;

void csdb_init(void) {
	uint32_t i;
	for (i=0 ; i<CSDB_HASHSIZE ; i++) {
		s_OpCntHash[i]=NULL;
	}
	s_OpLock = (pthread_mutex_t*)malloc(sizeof(pthread_mutex_t));
	pthread_mutex_init(s_OpLock,NULL);
}

void csdb_term(void) {
	uint32_t i;
	STCsOpEntry *cs,*csn;

	pthread_mutex_destroy(s_OpLock);
	free(s_OpLock);
	for (i=0 ; i<CSDB_HASHSIZE ; i++) {
		for (cs = s_OpCntHash[i] ; cs ; cs = csn) {
			csn = cs->next;
			free(cs);
		}
	}
}

uint32_t csdb_getreadcnt(uint32_t ip,uint16_t port) {
	uint32_t hash = CSDB_HASH(ip,port);
	uint32_t result = 0;
	pthread_mutex_lock(s_OpLock);
	for (STCsOpEntry *e=s_OpCntHash[hash] ; e ; e=e->next) {
		if (e->ip == ip && e->port == port) {
			result = e->readopcnt;
			break;
		}
	}
	pthread_mutex_unlock(s_OpLock);
	return result;
}

uint32_t csdb_getwritecnt(uint32_t ip,uint16_t port) {
	uint32_t hash = CSDB_HASH(ip,port);
	uint32_t result = 0;
	STCsOpEntry *e;
	pthread_mutex_lock(s_OpLock);
	for (e=s_OpCntHash[hash] ; e ; e=e->next) {
		if (e->ip == ip && e->port == port) {
			result = e->writeopcnt;
			break;
		}
	}
	pthread_mutex_unlock(s_OpLock);
	return result;
}

uint32_t csdb_getopcnt(uint32_t ip,uint16_t port) {
	uint32_t hash = CSDB_HASH(ip,port);
	uint32_t result = 0;
	pthread_mutex_lock(s_OpLock);
	for (STCsOpEntry *e=s_OpCntHash[hash] ; e ; e=e->next) {
		if (e->ip == ip && e->port == port) {
			result = e->readopcnt + e->writeopcnt;
			break;
		}
	}
	pthread_mutex_unlock(s_OpLock);
	return result;
}

void csdb_readinc(uint32_t ip,uint16_t port) {
	uint32_t hash = CSDB_HASH(ip,port);
	STCsOpEntry *e;
	pthread_mutex_lock(s_OpLock);
	for (e=s_OpCntHash[hash] ; e ; e=e->next) {
		if (e->ip == ip && e->port == port) {
			e->readopcnt++;
			pthread_mutex_unlock(s_OpLock);
			return;
		}
	}
	e = (STCsOpEntry*)malloc(sizeof(STCsOpEntry));
	e->ip = ip;
	e->port = port;
	e->readopcnt = 1;
	e->writeopcnt = 0;
	e->next = s_OpCntHash[hash];
	s_OpCntHash[hash] = e;
	pthread_mutex_unlock(s_OpLock);
}

void csdb_readdec(uint32_t ip,uint16_t port) {
	uint32_t hash = CSDB_HASH(ip,port);

    pthread_mutex_lock(s_OpLock);
	for (STCsOpEntry *e=s_OpCntHash[hash] ; e ; e=e->next) {
		if (e->ip == ip && e->port == port) {
			e->readopcnt--;
			pthread_mutex_unlock(s_OpLock);
			return;
		}
	}
	pthread_mutex_unlock(s_OpLock);
}

void csdb_writeinc(uint32_t ip,uint16_t port) {
	uint32_t hash = CSDB_HASH(ip,port);
	STCsOpEntry *e;
	pthread_mutex_lock(s_OpLock);
	for (e=s_OpCntHash[hash] ; e ; e=e->next) {
		if (e->ip == ip && e->port == port) {
			e->writeopcnt++;
			pthread_mutex_unlock(s_OpLock);
			return;
		}
	}

	e = (STCsOpEntry*)malloc(sizeof(STCsOpEntry));
	e->ip = ip;
	e->port = port;
	e->readopcnt = 0;
	e->writeopcnt = 1;
	e->next = s_OpCntHash[hash];
	s_OpCntHash[hash] = e;
	pthread_mutex_unlock(s_OpLock);
}

void csdb_writedec(uint32_t ip,uint16_t port) {
	uint32_t hash = CSDB_HASH(ip,port);
	pthread_mutex_lock(s_OpLock);
	for (STCsOpEntry *e=s_OpCntHash[hash] ; e ; e=e->next) {
		if (e->ip == ip && e->port == port) {
			e->writeopcnt--;
			pthread_mutex_unlock(s_OpLock);
			return;
		}
	}
	pthread_mutex_unlock(s_OpLock);
}
