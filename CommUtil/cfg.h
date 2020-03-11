/*
   Copyright 2005-2010 Jakub Kruszona-Zawadzki, Gemius SA.

   This file is part of MooseFS.

   MooseFS is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, version 3.

   MooseFS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with MooseFS.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _CFG_H_
#define _CFG_H_

#include <stdint.h>
#include <inttypes.h>

#ifndef INT64_C
#define INT32_C(value) __CONCAT(value, L)
#define UINT32_C(value) __CONCAT(value, UL)
#define INT64_C(c) (c ## LL)
#define UINT64_C(c) (c ## ULL)
#endif

#define _CONFIG_MAKE_PROTOTYPE(fname,type) type cfg_get##fname(const char *name,const type def)

int cfg_load (const char *fname,int logundefined);
int cfg_reload (void);
void cfg_term (void);

int cfg_isdefined(const char *name);

_CONFIG_MAKE_PROTOTYPE(str,char*);
_CONFIG_MAKE_PROTOTYPE(num,int);
_CONFIG_MAKE_PROTOTYPE(uint8,uint8_t);
_CONFIG_MAKE_PROTOTYPE(int8,int8_t);
_CONFIG_MAKE_PROTOTYPE(uint16,uint16_t);
_CONFIG_MAKE_PROTOTYPE(int16,int16_t);
_CONFIG_MAKE_PROTOTYPE(uint32,uint32_t);
_CONFIG_MAKE_PROTOTYPE(int32,int32_t);
_CONFIG_MAKE_PROTOTYPE(uint64,uint64_t);
_CONFIG_MAKE_PROTOTYPE(int64,int64_t);
_CONFIG_MAKE_PROTOTYPE(double,double);

#endif
