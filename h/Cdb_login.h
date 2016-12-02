/*
 * Cdb_login.h,v 1.5 2000/02/16 17:31:46 jdurand Exp
 */

#ifndef __Cdb_login_h
#define __Cdb_login_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>              /* For all types  */

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"                  /* Externalization                            */
#include "Cdb_ana.h"                /* Description of the database as a structure */

#ifdef CDB_DEBUG
#ifndef CDB_LOGIN_DEBUG
#define CDB_LOGIN_DEBUG 1
#endif
#endif

#ifndef CDB_LOGIN_DEBUG
#define CDB_LOGIN_DEBUG 0
#endif

/* ======== */
/* Typedefs */
/* ======== */
struct Cdb_login {
  char *username;
  char *password;
  int   privilege;
  char *gecos;
  char *databases;
  struct Cdb_login *next;
};
typedef struct Cdb_login Cdb_login_t;

/* ====== */
/* Macros */
/* ====== */
#ifdef CDB_LOGIN_NOOP_PRIVILEGE
#undef CDB_LOGIN_NOOP_PRIVILEGE
#endif
#define CDB_LOGIN_NOOP_PRIVILEGE 1

#ifdef CDB_LOGIN_ADMIN_PRIVILEGE
#undef CDB_LOGIN_ADMIN_PRIVILEGE
#endif
#define CDB_LOGIN_ADMIN_PRIVILEGE 2

#ifdef CDB_LOGIN_READ_PRIVILEGE
#undef CDB_LOGIN_READ_PRIVILEGE
#endif
#define CDB_LOGIN_READ_PRIVILEGE 4

#ifdef CDB_LOGIN_WRITE_PRIVILEGE
#undef CDB_LOGIN_WRITE_PRIVILEGE
#endif
#define CDB_LOGIN_WRITE_PRIVILEGE 8

EXTERN_C int DLL_DECL Cdb_login_isallowed _PROTO((Cdb_login_t *, char *, int));
EXTERN_C int DLL_DECL Cdb_login_get _PROTO((Cdb_login_t **, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_login_free _PROTO((Cdb_login_t *));
EXTERN_C int DLL_DECL Cdb_login_new_user _PROTO((char *, char *, char *, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_login_delete_user _PROTO((char *, char *, char *, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_login_new_db _PROTO((char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_login_delete_db _PROTO((char *, char *, char *));

#endif /* __Cdb_login_h */

/*
 * Last Update: "Wednesday 16 February, 2000 at 07:48:27 CET by Jean-Damien Durand (<A HREF=mailto:Jean-Damien.Durand@cern.ch>Jean-Damien.Durand@cern.ch</A>)"
 */
