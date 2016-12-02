/*
 * Cdb_api.h,v 1.33 2000/05/31 08:54:49 jdurand Exp
 */

#ifndef __Cdb_api_h
#define __Cdb_api_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>
#include <stddef.h>           /* For size_t           */

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"            /* For u_signed64       */

/* ======== */
/* Typedefs */
/* ======== */
/* Offset type for all architectures */
typedef u_signed64 Cdb_off_t;

/* Size type for all architectures */
typedef u_signed64 Cdb_size_t;

/* Session structure */
struct Cdb_sess {
  int sendfd;                  /* Write   file descriptor */
  int recvfd;                  /* Receive file descriptor - only used in two sockets configuration */
  int timeout;                 /* Socket timeout */
  int deadlockretry;           /* Deadlock retry */
  int lockdenyretry;           /* Lock deny retry */
  char *error;                 /* Error buffer */
  int ndb;                     /* Number of opened db     */
  Cdb_size_t xxxfile_dump_size; /* For xxxfile dump */
  struct Cdb_db *db;           /* Linked list of databases */
};
typedef struct Cdb_sess Cdb_sess_t;

/* Database structure */
struct Cdb_db {
  char *name;                 /* Database name           */
  int (*Cdb_interface) _PROTO((char *, char *, int, void *, void *, size_t *)); /* Generated interface */
  void *mdata;               /* Marshalled data buffer   */
  size_t mdata_maxsize;      /* Marshalled data max size */
  Cdb_sess_t *session;       /* Session pointer          */
  struct Cdb_db *next;       /* Next database structure  */
};
typedef struct Cdb_db Cdb_db_t;

/* ====== */
/* Macros */
/* ====== */

#define CDB_CLIENT_ACCEPT_TIMEOUT 5 /* Only use in two sockets configuration when Cdb_server calls back */

#ifndef STGCONVERT
/* To avoid define clashes while building stage/stgconvert tool */
#define Cdb_login              Cdb_api_login
#define Cdb_logout             Cdb_api_logout
#define Cdb_login_add_user     Cdb_api_login_add_user
#define Cdb_login_remove_user  Cdb_api_login_remove_user
#define Cdb_login_add_db       Cdb_api_login_add_db
#define Cdb_db_add             Cdb_api_db_add
#define Cdb_db_remove          Cdb_api_db_remove
#define Cdb_open               Cdb_api_open
#define Cdb_close              Cdb_api_close
#define Cdb_fetch              Cdb_api_fetch
#define Cdb_insert             Cdb_api_insert
#define Cdb_update             Cdb_api_update
#define Cdb_pkeyfind_fetch     Cdb_api_pkeyfind_fetch
#define Cdb_pkeynext_fetch     Cdb_api_pkeynext_fetch
#define Cdb_pkeyprev_fetch     Cdb_api_pkeyprev_fetch
#define Cdb_keyfind_fetch      Cdb_api_keyfind_fetch
#define Cdb_keynext_fetch      Cdb_api_keynext_fetch
#define Cdb_keyprev_fetch      Cdb_api_keyprev_fetch
#define Cdb_unlock             Cdb_api_unlock
#define Cdb_delete             Cdb_api_delete
#define Cdb_uniqueid           Cdb_api_uniqueid
#define Cdb_shutdown           Cdb_api_shutdown
#define Cdb_error              Cdb_api_error
#define Cdb_unlock_all         Cdb_api_unlock_all
#define Cdb_dump_start         Cdb_api_dump_start
#define Cdb_dump               Cdb_api_dump
#define Cdb_dump_end           Cdb_api_dump_end
#define Cdb_ping               Cdb_api_ping
#define Cdb_pwdfile_dump_start Cdb_api_pwdfile_dump_start
#define Cdb_xxxfile_dump_size  Cdb_api_xxxfile_dump_size
#define Cdb_xxxfile_dump       Cdb_api_xxxfile_dump
#define Cdb_xxxfile_dump_end   Cdb_api_xxxfile_dump_end
#define Cdb_debuglevel         Cdb_api_debuglevel
#define Cdb_firstrow           Cdb_api_firstrow
#define Cdb_nextrow            Cdb_api_nextrow
#define Cdb_init               Cdb_api_init
#define Cdb_desfile_dump_start Cdb_api_desfile_dump_start

#define Cdb_pkeyfind(db,tablename,keyname,nfields,persistent_lock,data,newoffset) \
              Cdb_pkeyfind_fetch(db,tablename,keyname,nfields,persistent_lock,data,newoffset,NULL)
#define Cdb_pkeyprev(db,tablename,keyname,nfields,persistent_lock,newoffset) \
              Cdb_pkeyprev_fetch(db,tablename,keyname,nfields,persistent_lock,newoffset,NULL)
#define Cdb_pkeynext(db,tablename,keyname,nfields,persistent_lock,newoffset) \
              Cdb_pkeynext_fetch(db,tablename,keyname,nfields,persistent_lock,newoffset,NULL)
#define Cdb_keyfind(db,tablename,keyname,persistent_lock,data,newoffset) \
              Cdb_keyfind_fetch(db,tablename,keyname,persistent_lock,data,newoffset,NULL)
#define Cdb_keyprev(db,tablename,keyname,persistent_lock,newoffset) \
              Cdb_keyprev_fetch(db,tablename,keyname,persistent_lock,newoffset,NULL)
#define Cdb_keynext(db,tablename,keyname,persistent_lock,newoffset) \
              Cdb_keynext_fetch(db,tablename,keyname,persistent_lock,newoffset,NULL)
#endif /* STGCONVERT */

EXTERN_C int DLL_DECL Cdb_api_login _PROTO((char *, char *, Cdb_sess_t *));
EXTERN_C int DLL_DECL Cdb_api_logout _PROTO((Cdb_sess_t *));
EXTERN_C int DLL_DECL Cdb_api_login_add_user _PROTO((Cdb_sess_t *, char *, char *, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_api_login_remove_user _PROTO((Cdb_sess_t *, char *, char *, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_api_login_add_db _PROTO((Cdb_sess_t *, char *, char *));
EXTERN_C int DLL_DECL Cdb_api_login_remove_db _PROTO((Cdb_sess_t *, char *, char *));
EXTERN_C int DLL_DECL Cdb_api_db_add _PROTO((Cdb_sess_t *, char *, char *, size_t));
EXTERN_C int DLL_DECL Cdb_api_db_remove _PROTO((Cdb_sess_t *, char *));
EXTERN_C int DLL_DECL Cdb_api_open _PROTO((Cdb_sess_t *, char *, int (*) _PROTO((char *, char *, int, void *, void *, size_t *)), Cdb_db_t *));
EXTERN_C int DLL_DECL Cdb_api_close _PROTO((Cdb_db_t *));
EXTERN_C int DLL_DECL Cdb_api_fetch _PROTO((Cdb_db_t *, char *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_insert _PROTO((Cdb_db_t *, char *, char *, void *, Cdb_off_t *));
EXTERN_C int DLL_DECL Cdb_api_update _PROTO((Cdb_db_t *, char *, void *, Cdb_off_t *, Cdb_off_t *));
EXTERN_C int DLL_DECL Cdb_api_pkeyfind_fetch _PROTO((Cdb_db_t *, char *, char *, int, char *, void *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_pkeynext_fetch _PROTO((Cdb_db_t *, char *, char *, int, char *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_pkeyprev_fetch _PROTO((Cdb_db_t *, char *, char *, int, char *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_keyfind_fetch _PROTO((Cdb_db_t *, char *, char *, char *, void *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_keyprev_fetch _PROTO((Cdb_db_t *, char *, char *, char *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_keynext_fetch _PROTO((Cdb_db_t *, char *, char *, char *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_unlock _PROTO((Cdb_db_t *, char *, Cdb_off_t *));
EXTERN_C int DLL_DECL Cdb_api_delete _PROTO((Cdb_db_t *, char *, Cdb_off_t *));
EXTERN_C int DLL_DECL Cdb_api_uniqueid _PROTO((Cdb_db_t *, char *, u_signed64, u_signed64, u_signed64 *));
EXTERN_C int DLL_DECL Cdb_api_shutdown _PROTO((Cdb_sess_t *));
EXTERN_C int DLL_DECL Cdb_api_error _PROTO((Cdb_sess_t *, char **));
EXTERN_C int DLL_DECL Cdb_api_unlock_all _PROTO((Cdb_sess_t *));
EXTERN_C int DLL_DECL Cdb_api_dump_start _PROTO((Cdb_db_t *, char *));
EXTERN_C int DLL_DECL Cdb_api_dump _PROTO((Cdb_db_t *, char *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_dump_end _PROTO((Cdb_db_t *, char *));
EXTERN_C int DLL_DECL Cdb_api_ping _PROTO((Cdb_sess_t *));
EXTERN_C int DLL_DECL Cdb_api_pwdfile_dump_start _PROTO((Cdb_sess_t *));
EXTERN_C int DLL_DECL Cdb_api_xxxfile_dump_size _PROTO((Cdb_sess_t *, Cdb_size_t *));
EXTERN_C int DLL_DECL Cdb_api_xxxfile_dump _PROTO((Cdb_sess_t *, Cdb_size_t *, char **));
EXTERN_C int DLL_DECL Cdb_api_xxxfile_dump_end _PROTO((Cdb_sess_t *));
EXTERN_C int DLL_DECL Cdb_api_debuglevel _PROTO((Cdb_sess_t *, int));
EXTERN_C int DLL_DECL Cdb_api_firstrow _PROTO((Cdb_db_t *, char *, char *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_nextrow _PROTO((Cdb_db_t *, char *, char *, Cdb_off_t *, void *));
EXTERN_C int DLL_DECL Cdb_api_init _PROTO((Cdb_sess_t *));
EXTERN_C int DLL_DECL Cdb_api_desfile_dump_start _PROTO((Cdb_sess_t *, char *));

#endif /* __Cdb_api_h */

/*
 * Last Update: "Wednesday 31 May, 2000 at 10:12:17 CEST by Jean-Damien Durand (<A HREF='mailto:Jean-Damien.Durand@cern.ch'>Jean-Damien.Durand@cern.ch</A>)"
 */
