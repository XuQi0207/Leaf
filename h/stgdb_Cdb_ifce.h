/*
  stgdb_Cdb_ifce.h,v 1.6 2001/12/13 17:50:27 jdurand Exp
*/

#ifndef __stgdb_Cdb_ifce_h
#define __stgdb_Cdb_ifce_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>
#include <stddef.h>

/* ============= */
/* Local headers */
/* ============= */
#include "Cdb_api.h"
#include "osdep.h"
#include "stage_struct.h"
#include "Castor_limits.h"

/* ======== */
/* Typedefs */
/* ======== */
struct stgdb_fd {
  Cdb_sess_t Cdb_sess;
  Cdb_db_t   Cdb_db;
  char       username[CA_MAXUSRNAMELEN];
  char       password[CA_MAXUSRNAMELEN];
};
typedef struct stgdb_fd stgdb_fd_t;


#define stgdb_login(a) Stgdb_login(a,__FILE__,__LINE__)
#define stgdb_logout(a) Stgdb_logout(a,__FILE__,__LINE__)
#define stgdb_open(a,b) Stgdb_open(a,b,__FILE__,__LINE__)
#define stgdb_close(a) Stgdb_close(a,__FILE__,__LINE__)
#define stgdb_load(a,b,c,d,e,f,g) Stgdb_load(a,b,c,d,e,f,g,__FILE__,__LINE__)
#define stgdb_upd_stgcat(a,b) Stgdb_upd_stgcat(a,b,__FILE__,__LINE__)
#define stgdb_upd_stgpath(a,b) Stgdb_upd_stgpath(a,b,__FILE__,__LINE__)
#define stgdb_del_stgcat(a,b) Stgdb_del_stgcat(a,b,__FILE__,__LINE__)
#define stgdb_del_stgpath(a,b) Stgdb_del_stgpath(a,b,__FILE__,__LINE__)
#define stgdb_ins_stgcat(a,b) Stgdb_ins_stgcat(a,b,__FILE__,__LINE__)
#define stgdb_ins_stgpath(a,b) Stgdb_ins_stgpath(a,b,__FILE__,__LINE__)
#define stgdb_uniqueid(a,b) Stgdb_uniqueid(a,b,__FILE__,__LINE__)

EXTERN_C int DLL_DECL Stgdb_login _PROTO((stgdb_fd_t *, char *, int));
EXTERN_C int DLL_DECL Stgdb_logout _PROTO((stgdb_fd_t *, char *, int));
EXTERN_C int DLL_DECL Stgdb_open  _PROTO((stgdb_fd_t *, char *, char *, int));
EXTERN_C int DLL_DECL Stgdb_close  _PROTO((stgdb_fd_t *, char *, int));
EXTERN_C int DLL_DECL Stgdb_load  _PROTO((stgdb_fd_t *,
                                          struct stgcat_entry **,
                                          struct stgcat_entry **,
                                          size_t *,
                                          struct stgpath_entry **,
                                          struct stgpath_entry **,
                                          size_t *, char *, int));
EXTERN_C int DLL_DECL Stgdb_upd_stgcat _PROTO((stgdb_fd_t *, struct stgcat_entry *, char *, int));
EXTERN_C int DLL_DECL Stgdb_upd_stgpath _PROTO((stgdb_fd_t *, struct stgpath_entry *, char *, int));
EXTERN_C int DLL_DECL Stgdb_del_stgcat _PROTO((stgdb_fd_t *, struct stgcat_entry *, char *, int));
EXTERN_C int DLL_DECL Stgdb_del_stgpath _PROTO((stgdb_fd_t *, struct stgpath_entry *, char *, int));
EXTERN_C int DLL_DECL Stgdb_ins_stgcat _PROTO((stgdb_fd_t *, struct stgcat_entry *, char *, int));
EXTERN_C int DLL_DECL Stgdb_ins_stgpath _PROTO((stgdb_fd_t *, struct stgpath_entry *, char *, int));
EXTERN_C int DLL_DECL Stgdb_uniqueid _PROTO((stgdb_fd_t *, u_signed64 *, char *, int));

#endif /* __stgdb_Cdb_ifce_h */




