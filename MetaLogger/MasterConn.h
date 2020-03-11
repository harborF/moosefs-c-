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

#ifndef _MASTERCONN_H_
#define _MASTERCONN_H_

#include "DataPack.h"

class CMasterConn : public CConnEntry
{
public:
    static CMasterConn *s_Instance;
public:
    uint32_t bindip;
    uint32_t masterip;
    uint16_t masterport;
    uint8_t masteraddrvalid;

    uint8_t downloadretrycnt;
    uint8_t downloading;
    uint8_t oldmode;
    FILE *logfd;	// using stdio because this is text file
    int metafd;	// using standard unix I/O because this is binary file
    uint64_t filesize;
    uint64_t dloffset;
    uint64_t dlstartuts;
};

int masterconn_init(void);

#endif
