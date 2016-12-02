/*
 * Cdb_transaction.h,v 1.3 2000/02/16 17:31:48 jdurand Exp
 */

#ifndef __Cdb_transaction_h
#define __Cdb_transaction_h

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"              /* Externalization                  */
#include "Cdb_hash.h"           /* To get database structures       */

#define PAGE_SIZE         4096  /* Page size , in bytes             */
#define CDB_TRANSACTION_TIMEOUT 10 /* Mutex/Cond timeout            */

/* ================================================================ */
/* Based on "Lazy Consistency Using Loosely Synchronized Clocks" by */
/* Atul Adya and Barbara Liskov - Proceedings of the ACM Symposium  */
/*                                on Principles of Distributed      */
/*                                Computing (PODC'97),              */
/*                                Santa Barbara, CA, August 1997.   */
/* ================================================================ */
/* Nota: We restrict ourself to a single server, so we don't have   */
/* the synchronization problem, neither 2-phase commit.             */
/* ================================================================ */

/* ---------------------------------------------------------------- */
/* What is an object id                                             */
/* ---------------------------------------------------------------- */
struct oid {
  struct page *page;           /* Its Page */
  int ioid;                    /* Its number in that page */
  struct oid *next;            /* Next one */
};
typedef struct oid oid_t;

/* ---------------------------------------------------------------- */
/* What is a page : A list of objects per database file             */
/* ---------------------------------------------------------------- */
struct page {
  size_t page_size;            /* Size of this page                 */
  int idb;                     /* Concerned database name (mapped)  */
  int itable;                  /* Concerned table name in that db   */
  int noid;                    /* Number of objects in this page    */
  off_t *offset;               /* The objects offsets               */
  size_t *size;                /* The objects size                  */
  void **value;                /* The object values                 */
  struct page *next;           /* Next page */
};
typedef struct page page_t;

/* ---------------------------------------------------------------- */
/* What is a timestamp : time                                       */
/* ---------------------------------------------------------------- */
typedef time_t timestamp_t;     /* The localtime */

/* ---------------------------------------------------------------- */
/* What is a multistamp : A list of <client,timestamp>              */
/* ---------------------------------------------------------------- */
struct multistamp {
  int client;                   /* The client id (socket fd) */
                                /* Please note : no server id (we are unique) */
  timestamp_t timestamp;        /* Time timestamp */
  struct multistamp *next;      /* Next tuple */
};
typedef struct multistamp multistamp_t;

/* ---------------------------------------------------------------- */
/* ReadOnlySet : A list of read offsets                             */
/* ---------------------------------------------------------------- */
struct ros {
  oid_t *oid;                  /* Object ID */
  struct ros *next;            /* Next ReadOnlySet */
};
typedef struct ros ros_t;

/* ---------------------------------------------------------------- */
/* ModifiedOnlySet : A list of object IDs                           */
/* ---------------------------------------------------------------- */
struct mos {
  oid_t *oid;                  /* Object ID */
  struct mos *next;            /* Next ReadOnlySet */
};
typedef struct mos mos_t;

/* ---------------------------------------------------------------- */
/* NewOnlySet : A list of object IDs                                */
/* ---------------------------------------------------------------- */
struct nos {
  oid_t *oid;                  /* Object ID */
  struct nos *next;          /* Next ReadOnlySet */
};
typedef struct nos_t nos_t;

/* -------------------------------------------------------------------------- */
/* Validation queue: <transaction,ReadOnlySet,ModifiedOnlySet,timestamp,flag> */
/* -------------------------------------------------------------------------- */
struct vq {
  long long transaction;        /* Transaction id */
  int client;                   /* Client id (== socket fd) */
  int predicate;                /* Predicate for thread conditional variable */
  ros_t *ros;                   /* List of Read Only Set */
  mos_t *mos;                   /* List of Modified Only Set */
  multistamp_t *multistamp;     /* Corresponding multistamp */
  int flag;                     /* Flag (0=prepared,1=commited) */
  struct vq *next;              /* Next validation queue */
};
typedef struct vq vq_t;
  
/* ---------------------------------------------------------------- */
/* pstamp : map pages to multistamps                                */
/* ---------------------------------------------------------------- */
struct pstamp {
  page_t *page;             /* This page */
  multistamp_t *multistamp; /* With this multistamp */
  struct pstamp *next;      /* Next page stamp */
};
typedef struct pstamp pstamp_t;

/* -------------------------------------------------------------------------- */
/* ilist : List of invalidated objects ids per client at a given timestamp    */
/* -------------------------------------------------------------------------- */
struct ilist {
  int client;              /* This client */
  timestamp_t ts;          /* This timestamp */
  oid_t *oid;              /* Object IDs */
};
typedef struct ilist ilist_t;

/* ------ */
/* Macros */
/* ------ */
#ifdef CDB_TRANSACTION_PREPARED
#undef CDB_TRANSACTION_PREPARED
#endif
#define CDB_TRANSACTION_PREPARED 0

#ifdef CDB_TRANSACTION_COMMITED
#undef CDB_TRANSACTION_COMMITED
#endif
#define CDB_TRANSACTION_COMMITED 1

/* ------------------------ */
/* Functions for extern use */
/* ------------------------ */
EXTERN_C int DLL_DECL Cdb_transaction_start _PROTO((int, int *));
EXTERN_C int DLL_DECL Cdb_transaction_fetch _PROTO((Cdb_hash_db_t *, char *, off_t *, void **));

#endif /* __Cdb_transaction_h */

/*
 * Last Update: "Wednesday 16 February, 2000 at 07:48:52 CET by Jean-Damien Durand (<A HREF=mailto:Jean-Damien.Durand@cern.ch>Jean-Damien.Durand@cern.ch</A>)"
 */
