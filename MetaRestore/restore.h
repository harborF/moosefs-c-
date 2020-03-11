#ifndef _RESTORE_H_
#define _RESTORE_H_

#include <inttypes.h>

int restore(const char *filename,uint64_t lv,char *ptr);
void restore_setverblevel(uint8_t _vlevel);

#endif
