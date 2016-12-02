/*
 * Cdb_db.h,v 1.4 2000/02/16 17:31:42 jdurand Exp
 */

#ifndef __Cdb_db_h
#define __Cdb_db_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>              /* For all types  */

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"             /* Externalization                            */

#ifdef CDB_DB_ANAEXT
#undef CDB_DB_ANAEXT
#endif
#define CDB_DB_ANAEXT ".des"

#ifdef CDB_DEBUG
#ifndef CDB_DB_DEBUG
#define CDB_DB_DEBUG 1
#endif
#endif

#ifndef CDB_DB_DEBUG
#define CDB_DB_DEBUG 0
#endif

EXTERN_C int DLL_DECL Cdb_db_new _PROTO((char *, char *, char *, size_t));
EXTERN_C int DLL_DECL Cdb_db_delete _PROTO((char *, char *));

#endif /* __Cdb_db_h */

/*
 * Last Update: "Wednesday 16 February, 2000 at 07:48:05 CET by Jean-Damien Durand (<A HREF=mailto:Jean-Damien.Durand@cern.ch>Jean-Damien.Durand@cern.ch</A>)"
 */

