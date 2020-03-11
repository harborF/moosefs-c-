#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>

typedef struct _statsnode {
	uint64_t counter;
	uint8_t active;
	uint8_t absolute;
	char *name;
	char *fullname;
	uint32_t nleng;	// : strlen(name)
	uint32_t fnleng; // : strlen(fullname)
	struct _statsnode *firstchild;
	struct _statsnode *nextsibling;
} STStatsNode;

static STStatsNode *s_pNodeHead = NULL;
static uint32_t allactiveplengs = 0;
static uint32_t activenodes = 0;
static pthread_mutex_t glock = PTHREAD_MUTEX_INITIALIZER;

void stats_lock(void) {
	pthread_mutex_lock(&glock);
}

void stats_unlock(void) {
	pthread_mutex_unlock(&glock);
}

void* stats_get_subnode(void *node,const char *name,uint8_t absolute)
{
	STStatsNode *sn = (STStatsNode*)node;
	STStatsNode *a;
	pthread_mutex_lock(&glock);
	for (a=sn?sn->firstchild:s_pNodeHead ; a ; a=a->nextsibling) {
		if (strcmp(a->name,name)==0) {
			pthread_mutex_unlock(&glock);
			return a;
		}
	}

	a = (STStatsNode*)malloc(sizeof(STStatsNode));
	a->nextsibling = sn?sn->firstchild:s_pNodeHead;
	a->firstchild = NULL;
	a->counter = 0;
	a->active = 0;
	a->absolute = absolute;
	a->name = strdup(name);
	a->nleng = strlen(name);
	if (sn) {
		char *bstr;
		a->fnleng = sn->fnleng+1+a->nleng;
		bstr = (char*)malloc(a->fnleng+1);
		memcpy(bstr,sn->fullname,sn->fnleng);
		bstr[sn->fnleng]='.';
		memcpy(bstr+sn->fnleng+1,a->name,a->nleng);
		bstr[a->fnleng]=0;
		a->fullname = bstr;
	} else {
		a->fullname = a->name;
		a->fnleng = a->nleng;
	}
	if (sn) {
		sn->firstchild = a;
	} else {
		s_pNodeHead = a;
	}
	pthread_mutex_unlock(&glock);

	return a;
}

uint64_t* stats_get_counterptr(void *node)
{
	STStatsNode *sn = (STStatsNode*)node;
	pthread_mutex_lock(&glock);
	if (sn->active==0) {
		sn->active = 1;
		allactiveplengs += sn->fnleng;
		activenodes++;
	}
	pthread_mutex_unlock(&glock);
	return &(sn->counter);
}

static inline void stats_reset(STStatsNode *n)
{
	if (n->absolute==0) {
		n->counter = 0;
	}

	for (STStatsNode *a=n->firstchild ; a ; a=a->nextsibling) {
		stats_reset(a);
	}
}

void stats_reset_all(void) {
	pthread_mutex_lock(&glock);
	for (STStatsNode *a=s_pNodeHead ; a ; a=a->nextsibling) {
		stats_reset(a);
	}
	pthread_mutex_unlock(&glock);
}

static inline uint32_t stats_print_values(char *buff,uint32_t maxleng,STStatsNode *n) {
	uint32_t l;
	if (n->active) {
		l = snprintf(buff,maxleng,"%s: %"PRIu64"\n",n->fullname,n->counter);
	} else {
		l = 0;
	}

	for (STStatsNode *a=n->firstchild ; a ; a=a->nextsibling) {
		if (maxleng>l) {
			l += stats_print_values(buff+l,maxleng-l,a);
		}
	}

	return l;
}

static inline uint32_t stats_print_total(char *buff,uint32_t maxleng) {
	STStatsNode *a;
	uint32_t l;
	l = 0;
	for (a=s_pNodeHead ; a ; a=a->nextsibling) {
		if (maxleng>l) {
			l += stats_print_values(buff+l,maxleng-l,a);
		}
	}
	return l;
}

void stats_show_all(char **buff,uint32_t *leng) {
	uint32_t rl;
	pthread_mutex_lock(&glock);
	rl = allactiveplengs + 23*activenodes + 1;
	*buff = (char*)malloc(rl);
	if (*buff) {
		*leng = stats_print_total(*buff,rl);
	} else {
		*leng = 0;
	}
	pthread_mutex_unlock(&glock);
}

void stats_free(STStatsNode *n) {
	STStatsNode *a,*an;
	free(n->name);
	if (n->fullname != n->name) {
		free(n->fullname);
	}

	for (a=n->firstchild ; a ; a = an) {
		an = a->nextsibling;
		stats_free(a);
		free(a);
	}
}

void stats_term(void) {
	STStatsNode *a,*an;
	for (a=s_pNodeHead ; a ; a = an) {
		an = a->nextsibling;
		stats_free(a);
		free(a);
	}
}

