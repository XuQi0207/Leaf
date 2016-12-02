/*
 * Copyright (C) 2000 by CERN/IT/PDP/DM
 * All rights reserved
 */

/*
 * @(#)common.h,v 1.3 2001/01/30 13:31:58 CERN IT-PDP/DM Olof Barring
 */

/*
 * common.h   - common prototypes
 */

#ifndef _COMMON_H_INCLUDED_
#define _COMMON_H_INCLUDED_

#if !defined(_WIN32)
#include <sys/socket.h>                 /* Socket interface             */
#include <netinet/in.h>                 /* Internet data types          */
#else
#include <winsock2.h>
#endif

#include <Castor_limits.h>
#include <osdep.h>
#include <Cgetopt.h>
#include <Cglobals.h>
#include <Cnetdb.h>
#include <Cpool_api.h>
#include <Cpwd.h>
#include <Cthread_api.h>
#include <getacct.h>
#include <getacctent.h>
#include <log.h>
#include <net.h>
#include <serrno.h>
#include <socket_timeout.h>
#include <trace.h>
#include <u64subr.h>
#include <ypgetacctent.h>

EXTERN_C char DLL_DECL *getconfent_r _PROTO((char *, char *, int, char *, int));
EXTERN_C char DLL_DECL *getconfent _PROTO((char *, char *, int));
EXTERN_C int DLL_DECL setnetio _PROTO((int));
EXTERN_C int DLL_DECL solveln _PROTO((char *, char *, int));
EXTERN_C int DLL_DECL seelink _PROTO((char *, char *, int));
EXTERN_C int DLL_DECL isremote _PROTO((struct in_addr, char *));
EXTERN_C int DLL_DECL CDoubleDnsLookup _PROTO((SOCKET s, char *));
EXTERN_C int DLL_DECL isadminhost _PROTO((SOCKET s, char *));
EXTERN_C char DLL_DECL *getifnam_r _PROTO((SOCKET, char *, size_t));
EXTERN_C char DLL_DECL *getifnam _PROTO((SOCKET));
EXTERN_C int DLL_DECL get_user _PROTO((char *, char *, int, int, char *, int *, int *));

#endif /* _COMMON_H_INCLUDED_ */
