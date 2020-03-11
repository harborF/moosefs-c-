#include "config.h"
#include "topology.h"
#include "exports.h"
#include "DCacheMgr.h"
#include "ChunkCtrl.h"
#include "ClientCtrl.h"
#include "MetaLoggerCtrl.h"
#include "FileSysOpr.h"
#include "random.h"
#include "changelog.h"
#include "ChartsData.h"

#define STR_AUX(x) #x
#define STR(x) STR_AUX(x)
const char id[]="@(#) version: " STR(VERSMAJ) "." STR(VERSMID) "." STR(VERSMIN) ", written by Jakub Kruszona-Zawadzki";

/* Run Tab */
typedef int (*runfn)(void);
struct STRunTab{
	runfn fn;
	const char *name;
} RunTab[]={
	{changelog_init,"change log"},
	{rnd_init,"random generator"},
	{dcm_init,"data cache manager"}, // has to be before 'fs_init' and 'matoclserv_networkinit'
	{matoclserv_sessionsinit,"load stored sessions"}, // has to be before 'fs_init'
	{exports_init,"exports manager"},
	{topology_init,"net topology module"},
	{fs_init,"file system manager"},
	{chartsdata_init,"charts module"},
	{matomlserv_init,"communication with metalogger"},
	{matocsserv_init,"communication with chunkserver"},
	{matoclserv_networkinit,"communication with clients"},
	{(runfn)0,"****"}
},LateRunTab[]={
	{(runfn)0,"****"}
};
