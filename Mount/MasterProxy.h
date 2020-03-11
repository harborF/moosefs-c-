#ifndef _MASTERPROXY_H_
#define _MASTERPROXY_H_

#include <inttypes.h>

void masterproxy_getlocation(uint8_t *masterinfo);

void masterproxy_term(void);
int masterproxy_init(void);

#endif
