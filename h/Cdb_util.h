/*
 * Cdb_util.h,v 1.7 2002/06/03 09:21:26 jdurand Exp
 */

#ifndef __Cdb_util_h
#define __Cdb_util_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"

/* ====== */
/* Macros */
/* ====== */
#ifdef SLASH
#undef SLASH
#endif
#ifdef _WIN32
#define SLASH "\\"
#else
#define SLASH "/"
#endif

#ifdef CDB_DEBUG
#ifndef CDB_UTIL_DEBUG
#define CDB_UTIL_DEBUG 1
#endif
#endif

#ifndef CDB_UTIL_DEBUG
#define CDB_UTIL_DEBUG 0
#endif

#ifdef Cdb_util_checkdir
#undef Cdb_util_checkdir
#endif
#define Cdb_util_checkdir(a) Cdb_util_checkdir_public(a)

#if CDB_UTIL_DEBUG == 1
#ifdef Cdb_util_checkbuf
#undef Cdb_util_checkbuf
#endif
#define Cdb_util_checkbuf(a,b,c) Cdb_util_checkbuf_debug(__FILE__,__LINE__,a,b,c)
EXTERN_C int DLL_DECL Cdb_util_checkbuf_debug _PROTO((char *, int, void **, unsigned int *, unsigned int));

#else /* CDB_UTIL_DEBUG */

EXTERN_C int DLL_DECL Cdb_util_checkbuf _PROTO((void **, unsigned int *, unsigned int));

#endif /* CDB_UTIL_DEBUG */

EXTERN_C int DLL_DECL Cdb_util_dump _PROTO((char *, unsigned int));
EXTERN_C int DLL_DECL Cdb_util_dump_file _PROTO((char *));
EXTERN_C int DLL_DECL Cdb_util_checkdir_public _PROTO((char *));
EXTERN_C int DLL_DECL Cdb_util_checkdir_private _PROTO((char *));
EXTERN_C int DLL_DECL Cdb_util_readline _PROTO((int, char **, unsigned int *, char *, int));
EXTERN_C int DLL_DECL Cdb_util_str2ipaddr _PROTO((unsigned long *, char *));
EXTERN_C int DLL_DECL Cdb_util_ipaddr2str _PROTO((size_t, char *, unsigned long));

#endif /* __Cdb_util_h */
