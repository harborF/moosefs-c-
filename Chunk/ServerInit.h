#include "config.h"

#include <stdio.h>

#include "random.h"
#include "HddSpaceMgr.h"
#include "MasterConn.h"
#include "FrontConn.h"
#include "chartsdata.h"

#define STR_AUX(x) #x
#define STR(x) STR_AUX(x)
const char id[]="@(#) version: " STR(VERSMAJ) "." STR(VERSMID) "." STR(VERSMIN) ", written by Jakub Kruszona-Zawadzki";

/* Run Tab */
typedef int (*runfn)(void);
struct STRunTab{
	runfn fn;
	const char *name;
} RunTab[]={
	{rnd_init,"random generator"},
	{hdd_init,"hdd space manager"},
	{csserv_init,"main server module"},	/* it has to be before "MasterConn" */
	{masterconn_init,"master connection module"},
	{chartsdata_init,"charts module"},
	{(runfn)0,"****"}
},LateRunTab[]={
	{hdd_late_init,"hdd space manager - threads"},
	{(runfn)0,"****"}
};
