/*
 * Cdb_ana.h,v 1.9 2000/06/05 11:25:35 jdurand Exp
 */

#ifndef __Cdb_ana_h
#define __Cdb_ana_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>          /* For types                                */
#include <stdio.h>              /* For FILE                                 */

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"              /* For externalization                      */

/* ========================= */
/* Macros                    */
/* ========================= */
/* PS: I prefer to do it     */
/*     like this rather than */
/*     using enum            */
/* ========================= */

#ifdef CDB_DEBUG
#ifndef CDB_ANA_DEBUG
#define CDB_ANA_DEBUG 1
#endif
#endif

#ifndef CDB_ANA_DEBUG
#define CDB_ANA_DEBUG 0
#endif

#define CDB_ANA_DEF_INCLUDE "/usr/include"

#define CDB_TYPE_BYTE         1 /* flag key's value as a byte               */
#define CDB_TYPE_SHORT        2 /* flag key's value as a short              */
#define CDB_TYPE_U_SHORT      3 /* flag key's value as a unsigned short     */
#define CDB_TYPE_INT          4 /* flag key's value as an int               */
#define CDB_TYPE_U_INT        5 /* flag key's value as an unsigned int      */
#define CDB_TYPE_LONG         6 /* flag key's value as a long               */
#define CDB_TYPE_U_LONG       7 /* flag key's value as a unsigned long      */
#define CDB_TYPE_HYPER        8 /* flag key's value as a signed64           */
#define CDB_TYPE_U_HYPER      9 /* flag key's value as a u_signed64         */
#define CDB_TYPE_CHAR        10 /* flag key's value as a char               */
#define CDB_TYPE_U_CHAR      11 /* flag key's value as a unsigned char      */
#define CDB_TYPE_STRUCT      12 /* flag key's value as a structure          */
#define CDB_TYPE_UID_T       13 /* flag key's value as a uid_t              */
#define CDB_TYPE_GID_T       14 /* flag key's value as a gid_t              */
#define CDB_TYPE_TIME_T      15 /* flag key's value as a time_t             */
#define CDB_TYPE_MODE_T      16 /* flag key's value as a mode_t             */
#define CDB_TYPE_OFF_T       17 /* flag key's value as a off_t              */
#define CDB_TYPE_SIZE_T      18 /* flag key's value as a size_t             */
#define CDB_TYPE_LONG32      19 /* flag key's value as a LONG (32 bits)     */
#define CDB_TYPE_U_LONG32    20 /* flag key's value as a U_LONG (32 bits)   */

#define CDB_KEY_ORDER       101 /* key's ordering                           */
#define CDB_KEY_MEMBER      102 /* key's member                             */
#define CDB_KEY_HASHSIZE    103 /* key's hashsize                           */
#define CDB_KEY_FREEHASHSIZE 104 /* key's free list hashsize                */

#define CDB_KEY_ASCENDING     1 /* Key's ascending order                    */
#define CDB_KEY_NONE          0 /* Key's no sort order                      */
#define CDB_KEY_DESCENDING   -1 /* Key's descending order                   */

#define CDB_LEVEL_DB        301 /* Database level in description            */
#define CDB_LEVEL_TABLE     302 /* Record_type level in description         */
#define CDB_LEVEL_KEY       303 /* Key level in description                 */
#define CDB_LEVEL_END       304 /* End-of-level in description              */
#define CDB_LEVEL_UNIQUEKEY 305 /* Unique Key level in description          */

/* ------------------------------------------------------------------------ */
/* Definition of what is a column, eg a member of the record_type           */
/* ------------------------------------------------------------------------ */
struct Cdb_ana_col_t {
  char             *name;       /* Member name                              */
  int               type;       /* Member type                              */
  int               depth;      /* Depth (for structures)                   */
  int               nindices;   /* Number of indices                        */
  long             *indices;    /* List of indices                          */
  size_t max_marshalled_size;   /* Total maximum marshalled size            */
  size_t max_native_size;       /* Total maximum unmarshalled size          */
  struct Cdb_ana_col_t *prev;   /* Previous col                             */
  struct Cdb_ana_col_t *next;   /* Next col                                 */
};
typedef struct Cdb_ana_col_t Cdb_ana_col_t;

/* ------------------------------------------------------------------------ */
/* Definition of what is a key : assembly of members of record_type         */
/* ------------------------------------------------------------------------ */
struct Cdb_ana_key_t {
  char             *name;       /* Key name                                 */
  int               unique;     /* Unique flag                              */
  int               hashsize;   /* Hash table size                          */
  int           freehashsize;   /* Hash free table size                     */
  int               order;      /* Key order (ascending or descending)      */
  int               nmember;    /* Key number of table members              */
  char            **member;     /* Key composition in term of members       */
  size_t max_marshalled_size;   /* Total maximum marshalled size            */
  size_t max_native_size;       /* Total maximum unmarshalled size          */
  struct Cdb_ana_col_t **col;   /* Col description for each member          */
  struct Cdb_ana_key_t *prev;   /* Previous key                             */
  struct Cdb_ana_key_t *next;   /* Next key                                 */
};
typedef struct Cdb_ana_key_t Cdb_ana_key_t;

/* ------------------------------------------------------------------------ */
/* Definition of what is a table : a record_type and its keys               */
/* ------------------------------------------------------------------------ */
struct Cdb_ana_table_t {
  char             *name;       /* Record_type name                         */
  Cdb_ana_key_t        *key;    /* List of keys                             */
  Cdb_ana_col_t        *col;    /* List of columns                          */
  size_t max_marshalled_size;   /* Total maximum marshalled size            */
  size_t max_native_size;       /* Total maximum marshalled size            */
  struct Cdb_ana_table_t *prev; /* Previous table                           */
  struct Cdb_ana_table_t *next; /* Next table                               */
};
typedef struct Cdb_ana_table_t Cdb_ana_table_t;

/* ------------------------------------------------------------------------ */
/* Definition of what is a database : assembly of tables                    */
/* ------------------------------------------------------------------------ */
struct Cdb_ana_db_t {
  char             *name;       /* Database name                            */
  int               hashsize;   /* Hash table size                          */
  int           freehashsize;   /* Hash table free size                     */
  Cdb_ana_table_t      *table;      /* List of tables                       */
};
typedef struct Cdb_ana_db_t Cdb_ana_db_t;

/* ------------------------------------------------------------------------ */
/* Externalization                                                          */
/* ------------------------------------------------------------------------ */
EXTERN_C int DLL_DECL Cdb_ana _PROTO((char *, Cdb_ana_db_t **, int, char **));
EXTERN_C int DLL_DECL Cdb_ana_print _PROTO((FILE *, Cdb_ana_db_t *));
EXTERN_C int DLL_DECL Cdb_ana_export _PROTO((FILE *, Cdb_ana_db_t *));
EXTERN_C int DLL_DECL Cdb_ana_makec _PROTO((FILE *, char *, char *, char *, Cdb_ana_db_t *));
EXTERN_C int DLL_DECL Cdb_ana_makeh _PROTO((FILE *, char *, char *, Cdb_ana_db_t *));
EXTERN_C int DLL_DECL Cdb_ana_isamember _PROTO((Cdb_ana_table_t *, char *, Cdb_ana_col_t **));
EXTERN_C int DLL_DECL Cdb_ana_free _PROTO((Cdb_ana_db_t *));

#endif /* __Cdb_ana_h */

/*
 * Last Update: "Monday 05 June, 2000 at 10:26:25 CEST by Jean-Damien Durand (<A HREF='mailto:Jean-Damien.Durand@cern.ch'>Jean-Damien.Durand@cern.ch</A>)"
 */
