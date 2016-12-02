/*
 * Cdb_cache.h,v 1.3 2000/02/16 17:31:41 jdurand Exp
 */

#ifndef __Cdb_cache_h
#define __Cdb_cache_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"        /* For externalization */

#ifdef CDB_DEBUG
#ifndef CDB_CACHE_DEBUG
#define CDB_CACHE_DEBUG 1
#endif
#endif

#ifndef CDB_CACHE_DEBUG
#define CDB_CACHE_DEBUG 0
#endif

/* Total cache size : this is the number of entries */
#ifdef CDB_CACHE_SIZE
#undef CDB_CACHE_SIZE
#endif
#define CDB_CACHE_SIZE 100

/* For mutex access */
#ifdef CDB_CACHE_LOCK_TIMEOUT
#undef CDB_CACHE_LOCK_TIMEOUT
#endif
#define CDB_CACHE_LOCK_TIMEOUT 10

struct Cdb_cache_buffer_t {
  int ifilename;                      /* Data filename */
  off_t offset;                       /* Data offset   */
  size_t datasize;                    /* Data size     */
  void *data;                         /* Data itself   */
};
typedef struct Cdb_cache_buffer_t Cdb_cache_buffer_t;

EXTERN_C int DLL_DECL Cdb_cache_init _PROTO(());
EXTERN_C int DLL_DECL Cdb_cache_read _PROTO((char *, off_t, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_cache_write _PROTO((char *, off_t,void *,size_t));
EXTERN_C int DLL_DECL Cdb_cache_clean _PROTO(());

#endif /* __Cdb_cache_h */

/*
 * Last Update: "Wednesday 16 February, 2000 at 07:47:54 CET by Jean-Damien Durand (<A HREF=mailto:Jean-Damien.Durand@cern.ch>Jean-Damien.Durand@cern.ch</A>)"
 */

