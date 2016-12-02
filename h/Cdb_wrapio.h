/*
 * Cdb_wrapio.h,v 1.7 2002/05/09 14:29:57 jdurand Exp
 */

#ifndef __Cdb_wrapio_h
#define __Cdb_wrapio_h

/* ============== */
/* System headers */
/* ============== */
#ifndef _WIN32
#include <unistd.h>
#else
#include <stddef.h>
#define ssize_t size_t
#endif

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"
#include "Cdb_error.h"

#ifdef CDB_WRAPIO_READ
#undef CDB_WRAPIO_READ
#endif
#define CDB_WRAPIO_READ(a,b,c) Cdb_wrapio_read(a,b,c,__FILE__,__LINE__)

#ifdef CDB_WRAPIO_ANONREAD
#undef CDB_WRAPIO_ANONREAD
#endif
#define CDB_WRAPIO_ANONREAD(a,b,c) Cdb_wrapio_read(a,b,c,NULL,-1)

#ifdef CDB_WRAPIO_WRITE
#undef CDB_WRAPIO_WRITE
#endif
#define CDB_WRAPIO_WRITE(a,b,c) Cdb_wrapio_write(a,b,c,__FILE__,__LINE__)

#ifdef CDB_DEBUG
#ifndef CDB_WRAPIO_DEBUG
#define CDB_WRAPIO_DEBUG 1
#endif
#endif

#ifndef CDB_WRAPIO_DEBUG
#define CDB_WRAPIO_DEBUG 0
#endif

EXTERN_C ssize_t DLL_DECL Cdb_wrapio_read _PROTO((int, void *, size_t, char *, int));
EXTERN_C ssize_t DLL_DECL Cdb_wrapio_write _PROTO((int, void *, size_t, char *, int));

#endif /* __Cdb_wrapio_h */






