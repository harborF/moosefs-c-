#ifndef _ITREE_H_
#define _ITREE_H_

#include <inttypes.h>

void* itree_rebalance(void *o);
void* itree_add_interval(void *o,uint32_t f,uint32_t t,uint32_t id);
uint32_t itree_find(void *o,uint32_t v);
void itree_freeall(void *o);

// void itree_show(void *o);

#endif
