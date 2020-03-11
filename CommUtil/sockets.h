#ifndef _SOCKETS_H_
#define _SOCKETS_H_

#include <inttypes.h>

/* ----------------- TCP ----------------- */

int tcpSocket(void);
int tcpResolve(const char *hostname,const char *service,uint32_t *ip,uint16_t *port,int passiveflag);
int tcpNonBlock(int sock);
int tcpSetAcceptFilter(int sock);
int tcpReuseAddr(int sock);
int tcpNoDelay(int sock);
int tcpAccfHttp(int sock);
int tcpAccfData(int sock);
int tcpNumBind(int sock,uint32_t ip,uint16_t port);
int tcpStrBind(int sock,const char *hostname,const char *service);
int tcpNumConnect(int sock,uint32_t ip,uint16_t port);
int tcpNumToConnect(int sock,uint32_t ip,uint16_t port,uint32_t msecto);
int tcpStrConnect(int sock,const char *hostname,const char *service);
int tcpStrToConnect(int sock,const char *hostname,const char *service,uint32_t msecto);
int tcpGetStatus(int sock);
int tcpNumListen(int sock,uint32_t ip,uint16_t port,uint16_t queue);
int tcpStrListen(int sock,const char *hostname,const char *service,uint16_t queue);
int tcpAccept(int lsock);
int tcpGetPeer(int sock,uint32_t *ip,uint16_t *port);
int tcpGetMyAddr(int sock,uint32_t *ip,uint16_t *port);
int tcpClose(int sock);
int32_t tcpToRead(int sock,void *buff,uint32_t leng,uint32_t msecto);
int32_t tcpToWrite(int sock,const void *buff,uint32_t leng,uint32_t msecto);
int tcpToAccept(int sock,uint32_t msecto);

/* ----------------- UDP ----------------- */

int udpsocket(void);
int udpresolve(const char *hostname,const char *service,uint32_t *ip,uint16_t *port,int passiveflag);
int udpnonblock(int sock);
int udpnumlisten(int sock,uint32_t ip,uint16_t port);
int udpstrlisten(int sock,const char *hostname,const char *service);
int udpwrite(int sock,uint32_t ip,uint16_t port,const void *buff,uint16_t leng);
int udpread(int sock,uint32_t *ip,uint16_t *port,void *buff,uint16_t leng);
int udpclose(int sock);

#endif
