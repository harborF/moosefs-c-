#ifndef _SERVER_CORE_H__
#define _SERVER_CORE_H__
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/time.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <inttypes.h>
#include "cfg.h"
#include "strerr.h"
#include "massert.h"
#include "slogger.h"

#define TIMEMODE_SKIP_LATE 0
#define TIMEMODE_RUN_LATE 1
#ifndef MFSMAXFILES
#define MFSMAXFILES 5000
#endif

#define STR_AUX(x) #x
#define STR(x) STR_AUX(x)

enum { RM_RESTART = 0, RM_START, RM_STOP, RM_RELOAD, RM_TEST, RM_KILL };

class CServerCore
{
    typedef struct RunEntry {
        void (*fun)(void);
        struct RunEntry *next;
    } RunEntry;

    typedef struct RunRetEntry {
        int (*fun)(void);
        struct RunRetEntry *next;
    } RunRetEntry;

    typedef struct PollRunEntry {
        void (*desc)(struct pollfd *,uint32_t *);
        void (*serve)(struct pollfd *);
        struct PollRunEntry *next;
    } PollRunEntry;

    typedef struct TimeRunEntry {
        uint32_t nextevent;
        uint32_t seconds;
        uint32_t offset;
        int mode;
        void (*fun)(void);
        struct TimeRunEntry *next;
    } TimeRunEntry;
public:
    static uint32_t s_now;
    static uint64_t s_usecnow;
private:
    RunEntry *m_destruct_head;
    RunEntry *m_wantexit_head;
    RunRetEntry *m_canexit_head;
    RunEntry *m_reload_head;
    RunEntry *m_eachloop_head;
    TimeRunEntry *m_time_head;
    PollRunEntry *m_poll_head;
protected:
    CServerCore();
public:
    ~CServerCore();
    static CServerCore* getInstance();
public:
    static inline uint32_t get_time(void){
        return s_now;
    }
    static uint64_t get_utime(void);
    static uint64_t get_precise_utime(void);

    static void signal_cleanup(void);
    static void set_signal_handlers(int dflag);
public:
    int canExit();
    void destruct();
    void mainloop();

    void free_all_entries();
    void destruct_register (void (*fun)(void));
    void canexit_register (int (*fun)(void));
    void wantexit_register (void (*fun)(void));
    void reload_register (void (*fun)(void));
    void eachloop_register (void (*fun)(void));

    void poll_register (void (*desc)(struct pollfd *,uint32_t *),void (*serve)(struct pollfd *));
    void* time_register (int mode,uint32_t seconds,uint32_t offset,void (*fun)(void));
    int time_change(void *x,int mode,uint32_t seconds,uint32_t offset);

public:
    static void wdunlock(void);
    static int wdlock(uint8_t runmode,uint32_t timeout);
    static int check_old_locks(uint8_t runmode,uint32_t timeout);
    static void remove_old_wdlock(void);
};

#endif
