/*
 * Cdb_hash.h,v 1.38 2000/06/05 11:41:29 jdurand Exp
 */

#ifndef __Cdb_hash_h
#define __Cdb_hash_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>        /* For all types  */

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"                  /* Externalization                            */
#include "Cdb_ana.h"                /* Description of the database as a structure */
#include "Cdb_login.h"              /* Login structure                            */

#ifdef CDB_DEBUG
#ifndef CDB_HASH_DEBUG
#define CDB_HASH_DEBUG 1
#endif
#endif

#ifndef CDB_HASH_DEBUG
#define CDB_HASH_DEBUG 0
#endif

#ifndef CDB_CACHE
#define CDB_CACHE 0                /* Default is no cache until I debug it... */
#endif

struct Cdb_hash_table {
  struct Cdb_hash_db *db;           /* Database to which it belongs */
  char *name;                       /* Table name (coming from Cdb_ana) */
  Cdb_ana_table_t *ana;             /* Table analysis (coming from Cdb_ana) */

  /* ---------------------- */
  /* For the Unique-ID file */
  /* ---------------------- */
  char *uniqueiduserfilename;       /* Unique-ID filename for the user */
  int uniqueiduserifilename;        /* Unique-ID user's ifilename for Cdb_lock */
  int uniqueiduserfd;               /* Unique-ID filename for the user */

  /* ------------ */
  /* For the dump */
  /* ------------ */
  int dumpikey;
  int dumpcurrenthash;
  off_t dumpptrval;

  /* ------------ */
  /* For the list */
  /* ------------ */
  int listikey;
  int listcurrenthash;
  off_t listptrval;
  off_t listoff;

  /* ----------------- */
  /* For the key files */
  /* ----------------- */
  int nkey;                         /* Number of keys */
  size_t *key_max_marshalled_size;  /* [nkey] key maximum marshalled size */
  char **keyfilename;               /* [nkey] key filenames */
  int *keyifilename;                /* [nkey] key ifilenames for Cdb_lock */
  char **keyname;                   /* [nkey] key names (coming from Cdb_ana) */
  int *keyhashsize;                 /* [nkey] key files hashsizes */
  int *keyfreehashsize;             /* [nkey] key files freehashsizes */
  Cdb_ana_key_t **keyana;           /* [nkey] Keys descriptions (coming from Cdb_ana) */
  int *keyfd;                       /* [nkey] key files fd */
  char **keybuf;                    /* [nkey] key buffer */
  size_t *keybuf_size;              /* [nkey] key buffers sizes */
  char **keyvalbuf;                 /* [nkey] key buffer (temporary value for inserting a new data) */
  size_t *keyvalbuf_size;           /* [nkey] key length of the temporarly value in keyvalbuf */
  char **keydummybuf;               /* [nkey] key buffer (temporary value for dragging in the keyfile) */
  size_t *keydummybuf_size;         /* [nkey] key length of the temporarly value in keydummybuf */

  /* Internaly used value for key index file */
  off_t *keyoff;                    /* [nkey] offset in index file */
  off_t *keychainoff;               /* [nkey] chain offset in the key file */
  off_t *keyptroff;                 /* [nkey] offset of the next unequal record */

  int *nnkey;                       /* [nkey] nnkey value : number of pkey files for this key */

  /* This is the keyfile information that will always be of a static size */
  /* after the offset in the next chain.                                  */
  off_t *keyptrval;                 /* [nkey] next offset in the key file chain */
  off_t *keyprev;                   /* [nkey] prev offset vs. order (in the same chain) */
  off_t *keynext;                   /* [nkey] next offset vs. order (in the same chain) */
  off_t *keydatoff;                 /* [nkey] offset in datafile for uniqueid */
  size_t *keydatlen;                /* [nkey] length in datafile for uniqueid */

  /* For a ROOT record only */
  size_t *keylen;                   /* [nkey] length of keyvalue in key file */
  off_t **keyjump;                  /* [nkey][nnkey] Chain of previous, Offset of previous, Chain of next, Offset of next */
  off_t **newkeyjump;               /* [nkey][nnkey] Temp buffer for Chain of previous, Offset of previous, Chain of next, Offset of next */

  /* ------------------ */
  /* For the pkey files */
  /* ------------------ */
  size_t **pkey_max_marshalled_size;/* [nkey][nnkey] key maximum marshalled size */
  char ***pkeyfilename;             /* [nkey][nnkey] pkey filenames */
  int **pkeyifilename;              /* [nkey][nnkey] pkey ifilenames for Cdb_lock */
  int **pkeyfd;                     /* [nkey][nnkey] pkey files fd */
  char ***pkeybuf;                  /* [nkey][nnkey] pkey buffer */
  size_t **pkeybuf_size;            /* [nkey][nnkey] pkey buffers sizes */
  char ***pkeyvalbuf;               /* [nkey][nnkey] pkey buffer (temporarly value) */
  size_t **pkeyvalbuf_size;         /* [nkey][nnkey] key length of the temporarly value in keyvalbuf */
  char ***pkeydummybuf;             /* [nkey][nnkey] pkey buffer (temporarly value when dragging in data) */
  size_t **pkeydummybuf_size;       /* [nkey][nnkey] key length of the temporarly value in keydummybuf */

  /* Internaly used value for pkey file */
  off_t **pkeyoff;                  /* [nkey][nnkey] offset in index file */
  off_t **pkeychainoff;             /* [nkey][nnkey] chain offset in the key file */
  off_t **pkeyptroff;               /* [nkey][nnkey] offset of the next unequal record */

  /* This is the pkey file information that will always be of a static size */
  /* after the offset in the next chain.                                  */
  off_t **pkeyptrval;               /* [nkey][nnkey] temporarly value for next offset in the key file chain */
  size_t **pkeylen;                 /* [nkey][nnkey] length of keyvalue in key file */
  off_t **pkeyjump_chain;           /* [nkey][nnkey] Chain offset in main key file */
  off_t **pkeyjump;                 /* [nkey][nnkey] Offset in main key file */

  /* ----------------- */
  /* For the data file */
  /* ----------------- */
  char *datfilename;                /* Data filename */
  int datifilename;                 /* Data ifilename for Cdb_lock */
  int datfd;                        /* Data file descriptor */
  size_t max_marshalled_size;       /* This is known in advance... */
  off_t datoff;                     /* Data offset */
  size_t datlen;                    /* Data length */
  void *datbuf;                     /* Data buffer */

  /* ------------------------------- */
  /* Pointers for key reconstruction */
  /* ------------------------------- */
  int *iptr;                         /* [nkey] */
  char **ptr;                        /* [nkey] */

  /* ---------------- */
  /* For optimization */
  /* ---------------- */
  off_t lastlock_offset;            /* Last data offset lock */

};
typedef struct Cdb_hash_table Cdb_hash_table_t;

struct Cdb_hash_db {
#ifdef CDB_CHECKMEM
  /* tables for memory debug checksum -  I put if there so that it is as fas as possible as original table pointer */
  Cdb_hash_table_t *checktable;
#endif
  struct Cdb_hash_session *session; /* Session to which it belongs */
  Cdb_ana_db_t *ana;       /* Description file analysis */
  char *name;              /* database name (not malloced) */
  int ntable;              /* number of tables */
  int hashsize;            /* Default hash table size */
  int freehashsize;        /* Default hash table free size */
  Cdb_hash_table_t *table; /* tables */
};
typedef struct Cdb_hash_db Cdb_hash_db_t;

struct Cdb_hash_session {
  char *username;           /* username login */
  char *password;           /* username password */
  Cdb_login_t *login;       /* login entries */
  int ndb;                  /* number of databases */
  Cdb_hash_db_t **db;       /* databases */
};
typedef struct Cdb_hash_session Cdb_hash_session_t;

EXTERN_C int DLL_DECL Cdb_hash_login _PROTO((char *, char *, char *, Cdb_hash_session_t **));
EXTERN_C int DLL_DECL Cdb_hash_login_add_user _PROTO((Cdb_hash_session_t *, char *, char *, char *, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_hash_login_remove_user _PROTO((Cdb_hash_session_t *, char *, char *, char *, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_hash_login_add_db _PROTO((Cdb_hash_session_t *, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_hash_login_remove_db _PROTO((Cdb_hash_session_t *, char *, char *, char *));
EXTERN_C int DLL_DECL Cdb_hash_logout _PROTO((Cdb_hash_session_t **));
EXTERN_C int DLL_DECL Cdb_hash_db_add _PROTO((Cdb_hash_session_t *, char *, char *, char *, size_t));
EXTERN_C int DLL_DECL Cdb_hash_db_remove _PROTO((Cdb_hash_session_t *, char *, char *));
EXTERN_C int DLL_DECL Cdb_hash_debuglevel _PROTO((Cdb_hash_session_t *));
EXTERN_C int DLL_DECL Cdb_hash_open _PROTO((Cdb_hash_session_t *, char *, char *));
EXTERN_C int DLL_DECL Cdb_hash_close _PROTO((Cdb_hash_session_t *, char *));
EXTERN_C int DLL_DECL Cdb_hash_fetch _PROTO((Cdb_hash_session_t *, char *, char *, int, off_t, size_t, void **, size_t *, int));
EXTERN_C int DLL_DECL Cdb_hash_insert _PROTO((Cdb_hash_session_t *, char *, char *, char *, void *, size_t, off_t *));
EXTERN_C int DLL_DECL Cdb_hash_update _PROTO((Cdb_hash_session_t *, char *, char *, void *, size_t, int, off_t, off_t *));
EXTERN_C int DLL_DECL Cdb_hash_delete _PROTO((Cdb_hash_session_t *, char *, char *, int, off_t));
EXTERN_C int DLL_DECL Cdb_hash_checkarg _PROTO((Cdb_hash_session_t *, char *, char *, Cdb_hash_db_t **, Cdb_hash_table_t **));
EXTERN_C int DLL_DECL Cdb_hash_pkeyfind _PROTO((Cdb_hash_session_t *, char *, char *, char *, char *, int, void *, size_t, off_t *, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_pkeynext _PROTO((Cdb_hash_session_t *, char *, char *, char *, char *, int, off_t *, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_pkeyprev _PROTO((Cdb_hash_session_t *, char *, char *, char *, char *, int, off_t *, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_keyfind _PROTO((Cdb_hash_session_t *, char *, char *, char *, char *, void *, size_t, off_t *, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_keynext _PROTO((Cdb_hash_session_t *, char *, char *, char *, char *, off_t *, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_keyprev _PROTO((Cdb_hash_session_t *, char *, char *, char *, char *, off_t *, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_find _PROTO((Cdb_hash_session_t *, char *, char *, char *, u_signed64, off_t *));
EXTERN_C int DLL_DECL Cdb_hash_unlock _PROTO((Cdb_hash_session_t *, char *, char *, int, off_t));
EXTERN_C int DLL_DECL Cdb_hash_uniqueid _PROTO((Cdb_hash_session_t *, char *, char *, u_signed64, u_signed64, u_signed64 *));
EXTERN_C int DLL_DECL Cdb_hash_shutdown _PROTO((Cdb_hash_session_t *));
EXTERN_C int DLL_DECL Cdb_hash_dump_start _PROTO((Cdb_hash_session_t *, char *, char *));
EXTERN_C int DLL_DECL Cdb_hash_dump _PROTO((Cdb_hash_session_t *, char *, char *, off_t *, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_dump_end _PROTO((Cdb_hash_session_t *, char *, char *));
EXTERN_C int DLL_DECL Cdb_hash_ping _PROTO((Cdb_hash_session_t *));
EXTERN_C int DLL_DECL Cdb_hash_pwdfile_dump_start _PROTO((Cdb_hash_session_t *, char *, int *, int *));
EXTERN_C int DLL_DECL Cdb_hash_xxxfile_dump_size _PROTO((Cdb_hash_session_t *, int *, int *, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_xxxfile_dump _PROTO((Cdb_hash_session_t *, int *, int *, size_t *, char **));
EXTERN_C int DLL_DECL Cdb_hash_xxxfile_dump_end _PROTO((Cdb_hash_session_t *, int *, int *, size_t *, char **, int));
EXTERN_C int DLL_DECL Cdb_hash_firstrow _PROTO((Cdb_hash_session_t *, char *, char *, char *, off_t *, void **, size_t *));
EXTERN_C int DLL_DECL Cdb_hash_nextrow _PROTO((Cdb_hash_session_t *, char *, char *, char *, off_t *, void **, size_t *));
#ifdef CDB_CHECKMEM
EXTERN_C void DLL_DECL Cdb_hash_table_checkmem _PROTO((Cdb_hash_table_t *, char *, int));
#define CDB_CHECKMEM_TABLE(arg) Cdb_hash_table_checkmem(arg,__FILE__,__LINE__)
#else
#define CDB_CHECKMEM_TABLE(arg)
#endif
EXTERN_C int DLL_DECL Cdb_hash_init _PROTO((Cdb_hash_session_t *));
EXTERN_C int DLL_DECL Cdb_hash_desfile_dump_start _PROTO((Cdb_hash_session_t *, char *, char *, int *, int *));

#endif /* __Cdb_hash_h */

/*
 * Last Update: "Monday 05 June, 2000 at 13:30:46 CEST by Jean-Damien Durand (<A HREF='mailto:Jean-Damien.Durand@cern.ch'>Jean-Damien.Durand@cern.ch</A>)"
 */
