/*
 * Cdb_limits.h,v 1.3 2000/12/13 10:42:01 jdurand Exp
 */

#ifndef __Cdb_limits_h
#define __Cdb_limits_h

/* ============= */
/* Local headers */
/* ============= */
#include "Castor_limits.h"

#define CDB_MAXDBNAMELEN      CA_MAXPATHLEN      /* Db name maximum length */
#define CDB_MAXTABLENAMELEN   CA_MAXPATHLEN      /* Table name maximum length */
#define CDB_MAXKEYNAMELEN     CA_MAXPATHLEN      /* Key name maximum length */
#define CDB_MAXREQSIZE        200000             /* Maximum request size for the malloc() */
#endif /* __Cdb_limits_h */
