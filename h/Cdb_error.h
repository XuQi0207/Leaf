/*
 * Cdb_error.h,v 1.8 2002/05/09 13:14:20 jdurand Exp
 */

#ifndef __Cdb_error_h
#define __Cdb_error_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>        /* For all types  */

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"            /* Externalization */
#include "Cdb_debug.h"

/* ====== */
/* Macros */
/* ====== */
#ifdef NAMEOFVAR
#undef NAMEOFVAR
#endif
#ifdef __STDC__
#define NAMEOFVAR(x) #x
#else
#define NAMEOFVAR(x) "x"
#endif

#ifdef LINE__STRING
#undef LINE__STRING
#endif
#define LINE__STRING(line) LINE___STRING(line)

#ifdef LINE___STRING
#undef LINE___STRING
#endif
#define LINE___STRING(line) NAMEOFVAR(line)

#ifdef ERROR
#undef ERROR
#endif
#define ERROR(function,systemflag) \
  Cdb_error_push("### " NAMEOFVAR(function) " error generated at " __FILE__ "." LINE__STRING(__LINE__),systemflag,CallerFile,CallerLine); \

#ifdef CDB_DEBUG
#ifndef CDB_ERROR_DEBUG
#define CDB_ERROR_DEBUG 1
#endif
#endif

#ifndef CDB_ERROR_DEBUG
#define CDB_ERROR_DEBUG 0
#endif

/* ========== */
/* Prototypes */
/* ========== */
EXTERN_C void DLL_DECL  Cdb_error_push _PROTO((char *, int, char *, int));
EXTERN_C void DLL_DECL  Cdb_error_clean _PROTO(());
EXTERN_C char DLL_DECL *Cdb_error_get _PROTO(());
EXTERN_C void DLL_DECL  Cdb_error_free _PROTO(());

/* Extended versions for optimization (avoid thread routines calling) */

EXTERN_C int  DLL_DECL  Cdb_error_init _PROTO((char ***, size_t **, size_t **));
EXTERN_C void DLL_DECL  Cdb_error_push_ext _PROTO((char *, int, char *, int, char **, size_t *, size_t *));
EXTERN_C void DLL_DECL  Cdb_error_clean_ext _PROTO((char **, size_t *));
EXTERN_C void DLL_DECL  Cdb_error_free_ext _PROTO((char **, size_t *, size_t *));


#endif /* __Cdb_error_h */

