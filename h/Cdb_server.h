/*
 * Cdb_server.h,v 1.6 2000/03/29 13:20:52 jdurand Exp
 */

#ifndef __Cdb_server_h
#define __Cdb_server_h

/* ====== */
/* Macros */
/* ====== */
#ifdef CDB_DEBUG
#ifndef CDB_SERVER_DEBUG
#define CDB_SERVER_DEBUG 1
#endif
#endif

#ifndef CDB_SERVER_DEBUG
#define CDB_SERVER_DEBUG 0
#endif

#ifdef CDB_SERVER_MUTEX_TIMEOUT
#undef CDB_SERVER_MUTEX_TIMEOUT
#endif
#define CDB_SERVER_MUTEX_TIMEOUT 10

#ifdef CDB_SERVER_ASSIGN_TIMEOUT
#undef CDB_SERVER_ASSIGN_TIMEOUT
#endif
#define CDB_SERVER_ASSIGN_TIMEOUT 10

#ifdef CDB_SERVER_ACCEPT_TIMEOUT
#undef CDB_SERVER_ACCEPT_TIMEOUT
#endif
#define CDB_SERVER_ACCEPT_TIMEOUT 5

#ifndef CDB_DNSCHECK
#define CDB_DNSCHECK 0
#endif

#endif /* __Cdb_server_h */

/*
 * Last Update: "Tuesday 28 March, 2000 at 16:40:21 CEST by Jean-Damien Durand (<A HREF=mailto:Jean-Damien.Durand@cern.ch>Jean-Damien.Durand@cern.ch</A>)"
 */
