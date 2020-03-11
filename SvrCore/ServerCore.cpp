#include "ServerCore.h"

uint32_t CServerCore::s_now;
uint64_t CServerCore::s_usecnow;

static int s_signalpipe[2];

/* signals */
static int termsignal[]={
    SIGTERM,
    -1
};

static int reloadsignal[]={
    SIGHUP,
    -1
};

static int ignoresignal[]={
    SIGQUIT,
#ifdef SIGPIPE
    SIGPIPE,
#endif
#ifdef SIGTSTP
    SIGTSTP,
#endif
#ifdef SIGTTIN
    SIGTTIN,
#endif
#ifdef SIGTTOU
    SIGTTOU,
#endif
#ifdef SIGINFO
    SIGINFO,
#endif
#ifdef SIGUSR1
    SIGUSR1,
#endif
#ifdef SIGUSR2
    SIGUSR2,
#endif
#ifdef SIGCHLD
    SIGCHLD,
#endif
#ifdef SIGCLD
    SIGCLD,
#endif
    -1
};

static int daemonignoresignal[]={
    SIGINT,
    -1
};

void termhandle(int signo) {
    signo = write(s_signalpipe[1],"\001",1); // killing two birds with one stone - use signo and do something with value returned by write :)
    (void)signo; // and then use this value to calm down compiler ;)
}

void reloadhandle(int signo) {
    signo = write(s_signalpipe[1],"\002",1); // see above
    (void)signo;
}

CServerCore::CServerCore(): m_destruct_head(NULL),
    m_wantexit_head(NULL), m_canexit_head(NULL),
    m_reload_head(NULL), m_eachloop_head(NULL),
    m_time_head(NULL), m_poll_head(NULL)
{
}

CServerCore::~CServerCore()
{
}

CServerCore* CServerCore::getInstance()
{
    static CServerCore s_Instance;
    return &s_Instance;
}

void CServerCore::set_signal_handlers(int dflag) 
{
    struct sigaction sa;
    uint32_t i;

    zassert(pipe(s_signalpipe));

#ifdef SA_RESTART
    sa.sa_flags = SA_RESTART;
#else
    sa.sa_flags = 0;
#endif
    sigemptyset(&sa.sa_mask);

    sa.sa_handler = termhandle;
    for (i=0 ; termsignal[i]>0 ; i++) {
        sigaction(termsignal[i],&sa,(struct sigaction *)0);
    }
    sa.sa_handler = reloadhandle;
    for (i=0 ; reloadsignal[i]>0 ; i++) {
        sigaction(reloadsignal[i],&sa,(struct sigaction *)0);
    }
    sa.sa_handler = SIG_IGN;
    for (i=0 ; ignoresignal[i]>0 ; i++) {
        sigaction(ignoresignal[i],&sa,(struct sigaction *)0);
    }
    sa.sa_handler = dflag?SIG_IGN:termhandle;
    for (i=0 ; daemonignoresignal[i]>0 ; i++) {
        sigaction(daemonignoresignal[i],&sa,(struct sigaction *)0);
    }
}

void CServerCore::signal_cleanup(void) 
{
    close(s_signalpipe[0]);
    close(s_signalpipe[1]);
}

uint64_t CServerCore::get_utime() {
    return s_usecnow;
}

uint64_t CServerCore::get_precise_utime() {
    struct timeval tv;
    gettimeofday(&tv,NULL);

    uint64_t r;
    r = tv.tv_sec;
    r *= 1000000;
    r += tv.tv_usec;

    return r;
}

void CServerCore::destruct_register(void (*fun)(void))
{
    RunEntry *aux=(RunEntry*)malloc(sizeof(RunEntry));
    passert(aux);
    aux->fun = fun;
    aux->next = m_destruct_head;
    m_destruct_head = aux;
}

void CServerCore::canexit_register(int (*fun)(void))
{
    RunRetEntry *aux=(RunRetEntry*)malloc(sizeof(RunRetEntry));
    passert(aux);
    aux->fun = fun;
    aux->next = m_canexit_head;
    m_canexit_head = aux;
}

void CServerCore::wantexit_register(void (*fun)(void))
{
    RunEntry *aux=(RunEntry*)malloc(sizeof(RunEntry));
    passert(aux);
    aux->fun = fun;
    aux->next = m_wantexit_head;
    m_wantexit_head = aux;
}

void CServerCore::reload_register(void (*fun)(void))
{
    RunEntry *aux=(RunEntry*)malloc(sizeof(RunEntry));
    passert(aux);
    aux->fun = fun;
    aux->next = m_reload_head;
    m_reload_head = aux;
}

void CServerCore::poll_register(void (*desc)(struct pollfd *,uint32_t *),void (*serve)(struct pollfd *))
{
    PollRunEntry *aux=(PollRunEntry*)malloc(sizeof(PollRunEntry));
    passert(aux);
    aux->desc = desc;
    aux->serve = serve;
    aux->next = m_poll_head;
    m_poll_head = aux;
}

void CServerCore::eachloop_register(void (*fun)(void)) 
{
    RunEntry *aux=(RunEntry*)malloc(sizeof(RunEntry));
    passert(aux);
    aux->fun = fun;
    aux->next = m_eachloop_head;
    m_eachloop_head = aux;
}

void* CServerCore::time_register(int mode,uint32_t seconds,uint32_t offset,void (*fun)(void))
{
    TimeRunEntry *aux;
    if (seconds==0 || offset>=seconds) {
        return NULL;
    }

    aux = (TimeRunEntry*)malloc(sizeof(TimeRunEntry));
    passert(aux);
    aux->nextevent = ((s_now / seconds) * seconds) + offset;
    while (aux->nextevent<s_now) {
        aux->nextevent+=seconds;
    }

    aux->seconds = seconds;
    aux->offset = offset;
    aux->mode = mode;
    aux->fun = fun;
    aux->next = m_time_head;
    m_time_head = aux;

    return aux;
}

int CServerCore::time_change(void* x,int mode,uint32_t seconds,uint32_t offset)
{
    TimeRunEntry *aux = (TimeRunEntry*)x;
    if (seconds==0 || offset>=seconds) {
        return -1;
    }

    aux->nextevent = ((s_now / seconds) * seconds) + offset;
    while (aux->nextevent<s_now) {
        aux->nextevent+=seconds;
    }
    aux->seconds = seconds;
    aux->offset = offset;
    aux->mode = mode;

    return 0;
}

void CServerCore::free_all_entries(void)
{
    RunEntry *rtmp = NULL;
    for (RunEntry *de = m_destruct_head; de ; de = rtmp) {
        rtmp = de->next;
        free(de);
    }

    RunRetEntry* rrtmp = NULL;
    for (RunRetEntry *ce = m_canexit_head; ce ; ce = rrtmp) {
        rrtmp = ce->next;
        free(ce);
    }

    for (RunEntry *we = m_wantexit_head; we ; we = rtmp) {
        rtmp = we->next;
        free(we);
    }

    for (RunEntry *re = m_reload_head; re ; re = rtmp) {
        rtmp = re->next;
        free(re);
    }

    PollRunEntry* ptmp = NULL;
    for (PollRunEntry *pe = m_poll_head; pe ; pe = ptmp) {
        ptmp = pe->next;
        free(pe);
    }

    for (RunEntry *ee = m_eachloop_head; ee ; ee = rtmp) {
        rtmp = ee->next;
        free(ee);
    }

    TimeRunEntry* ttmp = NULL;
    for (TimeRunEntry*te = m_time_head; te ; te = ttmp) {
        ttmp = te->next;
        free(te);
    }
}

int CServerCore::canExit()
{
    for (RunRetEntry *aux = m_canexit_head ; aux!=NULL ; aux=aux->next ) {
        if (aux->fun()==0) {
            return 0;
        }
    }

    return 1;
}

void CServerCore::destruct()
{
    for (RunEntry *deit = m_destruct_head ; deit!=NULL ; deit=deit->next ) {
        deit->fun();
    }
}

void CServerCore::mainloop()
{
    uint32_t prevtime = 0;
    struct timeval tv;
    PollRunEntry *pollit;
    TimeRunEntry *timeit;
    RunRetEntry *ceit;
    RunEntry  *weit, *rlit, *eloopit;

    uint32_t ndesc;
    int t = 0,r = 0, i;
    struct pollfd pdesc[MFSMAXFILES];
    
    while (t!=3) 
    {
        ndesc=1;
        pdesc[0].fd = s_signalpipe[0];
        pdesc[0].events = POLLIN;
        pdesc[0].revents = 0;
        for (pollit = m_poll_head; pollit != NULL ; pollit = pollit->next) {
            pollit->desc(pdesc,&ndesc);
        }

        i = poll(pdesc, ndesc, 50);

        gettimeofday(&tv,NULL);
        s_usecnow = tv.tv_sec;
        s_usecnow *= 1000000;
        s_usecnow += tv.tv_usec;
        s_now = tv.tv_sec;

        if (i<0) {
            if (errno==EAGAIN) {
                syslog(LOG_WARNING,"poll returned EAGAIN");
                usleep(100000);
                continue;
            }
            if (errno!=EINTR) {
                syslog(LOG_WARNING,"poll error: %s",strerr(errno));
                break;
            }
        } else {
            if ((pdesc[0].revents)&POLLIN) {
                uint8_t sigid;
                if (read(s_signalpipe[0],&sigid,1)==1) {
                    if (sigid=='\001' && t==0) {
                        syslog(LOG_NOTICE,"terminate signal received");
                        t = 1;
                    } else if (sigid=='\002') {
                        syslog(LOG_NOTICE,"reloading config files");
                        r = 1;
                    }
                }
            }

            for (pollit = m_poll_head; pollit != NULL ; pollit = pollit->next) {
                pollit->serve(pdesc);
            }
        }

        for (eloopit = m_eachloop_head; eloopit != NULL ; eloopit = eloopit->next) {
            eloopit->fun();
        }

        if (s_now<prevtime) {
            // time went backward !!! - recalculate "nextevent" time
            // adding previous_time_to_run prevents from running next event too soon.
            for (timeit = m_time_head; timeit != NULL ; timeit = timeit->next)
            {
                uint32_t previous_time_to_run = timeit->nextevent - prevtime;
                if (previous_time_to_run > timeit->seconds) {
                    previous_time_to_run = timeit->seconds;
                }

                timeit->nextevent = ((s_now / timeit->seconds) * timeit->seconds) + timeit->offset;
                while (timeit->nextevent <= s_now+previous_time_to_run) {
                    timeit->nextevent += timeit->seconds;
                }
            }
        } else if (s_now>prevtime+3600) {
            // time went forward !!! - just recalculate "nextevent" time
            for (timeit = m_time_head; timeit != NULL ; timeit = timeit->next) {
                timeit->nextevent = ((s_now / timeit->seconds) * timeit->seconds) + timeit->offset;
                while (s_now >= timeit->nextevent) {
                    timeit->nextevent += timeit->seconds;
                }
            }
        }

        for (timeit = m_time_head; timeit != NULL ; timeit = timeit->next)
        {
            if (s_now >= timeit->nextevent) {
                if (timeit->mode == TIMEMODE_RUN_LATE) {
                    while (s_now >= timeit->nextevent) {
                        timeit->nextevent += timeit->seconds;
                    }
                    timeit->fun();
                } else { /* timeit->mode == TIMEMODE_SKIP_LATE */
                    if (s_now == timeit->nextevent) {
                        timeit->fun();
                    }
                    while (s_now >= timeit->nextevent) {
                        timeit->nextevent += timeit->seconds;
                    }
                }
            }
        }//end for

        prevtime = s_now;
        if (t==0 && r) {
            cfg_reload();
            for (rlit = m_reload_head; rlit!=NULL ; rlit=rlit->next ) {
                rlit->fun();
            }
            r = 0;
        }

        if (t==1) {
            for (weit = m_wantexit_head ; weit!=NULL ; weit=weit->next ) {
                weit->fun();
            }
            t = 2;
        }

        if (t==2) {
            i = 1;
            for (ceit = m_canexit_head ; ceit!=NULL && i ; ceit=ceit->next ) {
                if (ceit->fun()==0) {
                    i=0;
                }
            }
            if (i) {
                t = 3;
            }
        }
    }
}
