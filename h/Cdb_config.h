/*
 * Cdb_config.h,v 1.23 2002/07/25 06:31:25 jdurand Exp
 */

/* --------------------------------------------------------------------------- */
/* Cdb configuration default values and functions                              */
/*                                                                             */
/* It concerns:                                                                */
/*                                                                             */
/*    -----------------------------------------------------------------------  */
/*   | What            | Server| Frequency  | API | Frequency   |  Default   | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | network timeout | YES   | Startup    | YES | Per connect |   10       | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | port number     | YES   | Startup    | YES | Per connect |  8999      | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | protocol type   | YES   | Fixed      | YES | Fixed       |  "tcp"     | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | service name    | YES   | Startup    | YES | Per connect |  "Cdb"     | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | host name       | NO    |            | YES | Per connect |  localhost | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | debug level     | YES   | Startup    | NO  |             |  0         | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | Root directory  | YES   | Startup    | NO  |             |  SPOOL     | */
/*   |                 |       |            |     |             | (or tmp)   | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | Password file   | YES   | Startup    | NO  |             |  Cdb.pwd   | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | Hashsize        | YES   | Startup    | NO  |             |  1009      | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | Freehashsize    | YES   | Startup    | NO  |             |  1009      | */
/*   | ----------------|-------|------------|-----|-------------|------------| */
/*   | Log filename    | YES   | Startup    | NO  |             |  Cdb.log   | */
/*   | --------------------------------------------------------------------- | */
/*   | Thread in pool  | YES   | Startup    | NO  |             |  10        | */
/*   | --------------------------------------------------------------------- | */
/*   | Deadlock Retry  | NO    |            | YES |             |  10        | */
/*   | --------------------------------------------------------------------- | */
/*   | Lock deny Retry | NO    |            | YES |             |  10        | */
/*   | --------------------------------------------------------------------- | */
/*   | TCP_NODELAY     | YES   | Startup    | YES |             | 1 (all)    | */
/*   |                 |       |            |     |             | 0 (__osf__)| */
/*   | --------------------------------------------------------------------- | */
/*   | SO_RCVBUF       | YES   | Startup    | YES |             |  16384     | */
/*   | --------------------------------------------------------------------- | */
/*   | SO_SNDBUF       | YES   | Startup    | YES |             |  16384     | */
/*   | --------------------------------------------------------------------- | */
/*   | SO_DEBUG        | YES   | Startup    | YES |             |  0         | */
/*   | --------------------------------------------------------------------- | */
/*   | TCP_RFC1323     | YES   | Startup    | YES |             |  1         | */
/*   | (_AIX only)     |       |            |     |             |            | */
/*   | --------------------------------------------------------------------- | */
/*   | TF_ACKNOW       | YES   | Startup    | YES |             |  1         | */
/*   | (_AIX and       |       |            |     |             |            | */
/*   |  __osf__ only)  |       |            |     |             |            | */
/*   | --------------------------------------------------------------------- | */
/*   | TF2_NODELACK    | YES   | Startup    | YES |             |  1         | */
/*   | (__osf__ only)  |       |            |     |             |            | */
/*   | --------------------------------------------------------------------- | */
/*   | TCP_FASTACK     | YES   | Startup    | YES |             |  1         | */
/*   | (IRIX5 only)    |       |            |     |             |            | */
/*   | --------------------------------------------------------------------- | */
/*   | IP_REJECT       | YES   | accept()   | NO  |             |  .*        | */
/*   | --------------------------------------------------------------------- | */
/*   | NAME_REJECT     | YES   | accept()   | NO  |             |  .*        | */
/*   | --------------------------------------------------------------------- | */
/*   | IP_TRUST        | YES   | accept()   | NO  |             |  .*        | */
/*   | --------------------------------------------------------------------- | */
/*   | NAME_TRUST      | YES   | accept()   | NO  |             |^DOMAIN_NAME| */
/*   |-----------------------------------------------------------------------| */
/*   | HOLE_IDX        | YES   | Startup    | NO  |             | 1          | */
/*   |-----------------------------------------------------------------------| */
/*   | HOLE_DAT        | YES   | Startup    | NO  |             | 1          | */
/*    -----------------------------------------------------------------------  */
/*                                                                             */
/* Nota: TCP_RFC1323  is specific to AIX                                       */
/*       TF_ACKNOW    is specific to AIX, OSF1                                 */
/*       TF2_NODELACK is specific to OSF1                                      */
/*       TCP_FASTACK  is specific to IRIX                                      */
/*                                                                             */
/*                                                                             */
/* --------------------------------------------------------------------------- */
#ifndef __Cdb_config_h
#define __Cdb_config_h

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"          /* Externalization */
#include "Cdb_constants.h"  /* Castor Coding style compliance */

/* ====== */
/* Macros */
/* ====== */
#ifndef CDB_PATH_CONFIG
#if defined(_WIN32)
#define CDB_PATH_CONFIG "%SystemRoot%\\system32\\drivers\\etc\\DBCONFIG"
#else
#define CDB_PATH_CONFIG "/etc/DBCONFIG"
#endif
#endif /* CDB_PATH_CONFIG */

/* Default Cdb send/recv timeout */
#ifdef CDB_DEFAULT_TIMEOUT
#undef CDB_DEFAULT_TIMEOUT
#endif
#define CDB_DEFAULT_TIMEOUT 20

/* Default Cdb server port number */
#ifdef CDB_DEFAULT_PORT
#undef CDB_DEFAULT_PORT
#endif
#define CDB_DEFAULT_PORT CDB_PORT

/* Default Cdb server protocol type */
#ifdef CDB_DEFAULT_PROTO
#undef CDB_DEFAULT_PROTO
#endif
#define CDB_DEFAULT_PROTO CDB_PROTO

/* Default Cdb server host (NULL means: localhost) */
#ifdef CDB_DEFAULT_HOST
#undef CDB_DEFAULT_HOST
#endif
#define CDB_DEFAULT_HOST CDB_HOST

/* Default Cdb debug level */
#ifdef CDB_DEFAULT_DEBUG
#undef CDB_DEFAULT_DEBUG
#endif
#define CDB_DEFAULT_DEBUG 0

/* Default Cdb root directory */
#ifdef CDB_DEFAULT_ROOTDIR
#undef CDB_DEFAULT_ROOTDIR
#endif
#ifdef SPOOL
#define CDB_DEFAULT_ROOTDIR SPOOL
#else
#ifdef _WIN32
#define CDB_DEFAULT_ROOTDIR "\\temp\Cdb"
#else
#define CDB_DEFAULT_ROOTDIR "/tmp/Cdb"
#endif
#endif

/* Default Cdb password filename */
#ifdef CDB_DEFAULT_PWDFILENAME
#undef CDB_DEFAULT_PWDFILENAME
#endif
#define CDB_DEFAULT_PWDFILENAME "Cdb.pwd"

/* Default Cdb hash size */
#ifdef CDB_DEFAULT_HASHSIZE
#undef CDB_DEFAULT_HASHSIZE
#endif
#define CDB_DEFAULT_HASHSIZE 1009

/* Default Cdb free hash size */
#ifdef CDB_DEFAULT_FREEHASHSIZE
#undef CDB_DEFAULT_FREEHASHSIZE
#endif
#define CDB_DEFAULT_FREEHASHSIZE 1009

/* Default Cdb log filename */
#ifdef CDB_DEFAULT_LOGFILENAME
#undef CDB_DEFAULT_LOGFILENAME
#endif
#define CDB_DEFAULT_LOGFILENAME "Cdb.log"

/* Default Cdb number of threads in the pool */
#ifdef CDB_DEFAULT_NTHREAD
#undef CDB_DEFAULT_NTHREAD
#endif
#define CDB_DEFAULT_NTHREAD 10

/* Default Deadlock Number of retries */
#ifdef CDB_DEFAULT_DEADLOCKRETRY
#undef CDB_DEFAULT_DEADLOCKRETRY
#endif
#define CDB_DEFAULT_DEADLOCKRETRY 10

/* Default Lock deny Number of retries */
#ifdef CDB_DEFAULT_LOCKDENYRETRY
#undef CDB_DEFAULT_LOCKDENYRETRY
#endif
#define CDB_DEFAULT_LOCKDENYRETRY 10

/* Default TCP_NODELAY socket option value */
#ifdef CDB_DEFAULT_TCP_NODELAY
#undef CDB_DEFAULT_TCP_NODELAY
#endif
#ifdef __osf__
#define CDB_DEFAULT_TCP_NODELAY 0
#else
#define CDB_DEFAULT_TCP_NODELAY 1
#endif

/* Default SO_RCVBUF socket option value */
#ifdef CDB_DEFAULT_SO_RCVBUF
#undef CDB_DEFAULT_SO_RCVBUF
#endif
#define CDB_DEFAULT_SO_RCVBUF 16384

/* Default SO_SNDBUF socket option value */
#ifdef CDB_DEFAULT_SO_SNDBUF
#undef CDB_DEFAULT_SO_SNDBUF
#endif
#define CDB_DEFAULT_SO_SNDBUF 16384

/* Default SO_DEBUG socket option value */
#ifdef CDB_DEFAULT_SO_DEBUG
#undef CDB_DEFAULT_SO_DEBUG
#endif
#define CDB_DEFAULT_SO_DEBUG 0

/* Default TCP_RFC1323 socket option value */
#ifdef CDB_DEFAULT_TCP_RFC1323
#undef CDB_DEFAULT_TCP_RFC1323
#endif
#define CDB_DEFAULT_TCP_RFC1323 1

/* Default TF_ACKNOW socket option value */
#ifdef CDB_DEFAULT_TF_ACKNOW
#undef CDB_DEFAULT_TF_ACKNOW
#endif
#define CDB_DEFAULT_TF_ACKNOW 1

/* Default TF2_NODELACK socket option value */
#ifdef CDB_DEFAULT_TF2_NODELACK
#undef CDB_DEFAULT_TF2_NODELACK
#endif
#define CDB_DEFAULT_TF2_NODELACK 1

/* Default TCP_FASTACK socket option value */
#ifdef CDB_DEFAULT_TCP_FASTACK
#undef CDB_DEFAULT_TCP_FASTACK
#endif
#define CDB_DEFAULT_TCP_FASTACK 1

/* Default IP reject regular expression */
#ifdef CDB_DEFAULT_IP_REJECT
#undef CDB_DEFAULT_IP_REJECT
#endif
#define CDB_DEFAULT_IP_REJECT ".*"

/* Default NAME reject regular expression */
#ifdef CDB_DEFAULT_NAME_REJECT
#undef CDB_DEFAULT_NAME_REJECT
#endif
#define CDB_DEFAULT_NAME_REJECT ".*"

/* Default IP trust regular expression */
#ifdef CDB_DEFAULT_IP_TRUST
#undef CDB_DEFAULT_IP_TRUST
#endif
#define CDB_DEFAULT_IP_TRUST ".*"

/* Default Hole policy in index files */
#ifdef CDB_DEFAULT_HOLE_IDX
#undef CDB_DEFAULT_HOLE_IDX
#endif
#define CDB_DEFAULT_HOLE_IDX 1

/* Default Hole policy in data files */
#ifdef CDB_DEFAULT_HOLE_DAT
#undef CDB_DEFAULT_HOLE_DAT
#endif
#define CDB_DEFAULT_HOLE_DAT 1

/* Cdb class in configuration file */
#ifdef CDB_CLASS
#undef CDB_CLASS
#endif
#define CDB_CLASS "CDB"

/* Cdb net timeout entry in Cdb class */
#ifdef CDB_CLASS_TIMEOUT
#undef CDB_CLASS_TIMEOUT
#endif
#define CDB_CLASS_TIMEOUT "TIMEOUT"

/* Cdb service entry in Cdb class */
#ifdef CDB_CLASS_PORT
#undef CDB_CLASS_PORT
#endif
#define CDB_CLASS_PORT "PORT"

/* Cdb host entry in Cdb class */
#ifdef CDB_CLASS_HOST
#undef CDB_CLASS_HOST
#endif
#define CDB_CLASS_HOST "HOST"

/* Cdb debug entry in Cdb class */
#ifdef CDB_CLASS_DEBUG
#undef CDB_CLASS_DEBUG
#endif
#define CDB_CLASS_DEBUG "DEBUG"

/* Cdb rootdir entry in Cdb class */
#ifdef CDB_CLASS_ROOTDIR
#undef CDB_CLASS_ROOTDIR
#endif
#define CDB_CLASS_ROOTDIR "ROOTDIR"

/* Cdb pwdfilename entry in Cdb class */
#ifdef CDB_CLASS_PWDFILENAME
#undef CDB_CLASS_PWDFILENAME
#endif
#define CDB_CLASS_PWDFILENAME "PWDFILENAME"

/* Cdb hashsize entry in Cdb class */
#ifdef CDB_CLASS_HASHSIZE
#undef CDB_CLASS_HASHSIZE
#endif
#define CDB_CLASS_HASHSIZE "HASHSIZE"

/* Cdb freehashsize entry in Cdb class */
#ifdef CDB_CLASS_FREEHASHSIZE
#undef CDB_CLASS_FREEHASHSIZE
#endif
#define CDB_CLASS_FREEHASHSIZE "FREEHASHSIZE"

/* Cdb log filename entry in Cdb class */
#ifdef CDB_CLASS_LOGFILENAME
#undef CDB_CLASS_LOGFILENAME
#endif
#define CDB_CLASS_LOGFILENAME "LOGFILENAME"

/* Cdb number of thread in the pool entry in Cdb class */
#ifdef CDB_CLASS_NTHREAD
#undef CDB_CLASS_NTHREAD
#endif
#define CDB_CLASS_NTHREAD "NTHREAD"

/* Cdb deadlock retry class */
#ifdef CDB_CLASS_DEADLOCKRETRY
#undef CDB_CLASS_DEADLOCKRETRY
#endif
#define CDB_CLASS_DEADLOCKRETRY "DEADLOCKRETRY"

/* Cdb lock deny retry class */
#ifdef CDB_CLASS_LOCKDENYRETRY
#undef CDB_CLASS_LOCKDENYRETRY
#endif
#define CDB_CLASS_LOCKDENYRETRY "LOCKDENYRETRY"

/* Cdb TCP_NODELAY entry in Cdb class */
#ifdef CDB_CLASS_TCP_NODELAY
#undef CDB_CLASS_TCP_NODELAY
#endif
#define CDB_CLASS_TCP_NODELAY "TCP_NODELAY"

/* Cdb SO_RCVBUF entry in Cdb class */
#ifdef CDB_CLASS_SO_RCVBUF
#undef CDB_CLASS_SO_RCVBUF
#endif
#define CDB_CLASS_SO_RCVBUF "SO_RCVBUF"

/* Cdb SO_SNDBUF entry in Cdb class */
#ifdef CDB_CLASS_SO_SNDBUF
#undef CDB_CLASS_SO_SNDBUF
#endif
#define CDB_CLASS_SO_SNDBUF "SO_SNDBUF"

/* Cdb SO_DEBUG entry in Cdb class */
#ifdef CDB_CLASS_SO_DEBUG
#undef CDB_CLASS_SO_DEBUG
#endif
#define CDB_CLASS_SO_DEBUG "SO_DEBUG"

/* Cdb TCP_RFC1323 entry in Cdb class */
#ifdef CDB_CLASS_TCP_RFC1323
#undef CDB_CLASS_TCP_RFC1323
#endif
#define CDB_CLASS_TCP_RFC1323 "TCP_RFC1323"

/* Cdb TF_ACKNOW entry in Cdb class */
#ifdef CDB_CLASS_TF_ACKNOW
#undef CDB_CLASS_TF_ACKNOW
#endif
#define CDB_CLASS_TF_ACKNOW "TF_ACKNOW"

/* Cdb TF2_NODELACK entry in Cdb class */
#ifdef CDB_CLASS_TF2_NODELACK
#undef CDB_CLASS_TF2_NODELACK
#endif
#define CDB_CLASS_TF2_NODELACK "TF2_NODELACK"

/* Cdb TCP_FASTACK entry in Cdb class */
#ifdef CDB_CLASS_TCP_FASTACK
#undef CDB_CLASS_TCP_FASTACK
#endif
#define CDB_CLASS_TCP_FASTACK "TCP_FASTACK"

/* Cdb IP_REJECT entry in Cdb class */
#ifdef CDB_CLASS_IP_REJECT
#undef CDB_CLASS_IP_REJECT
#endif
#define CDB_CLASS_IP_REJECT "IP_REJECT"

/* Cdb NAME_REJECT entry in Cdb class */
#ifdef CDB_CLASS_NAME_REJECT
#undef CDB_CLASS_NAME_REJECT
#endif
#define CDB_CLASS_NAME_REJECT "NAME_REJECT"

/* Cdb IP_TRUST entry in Cdb class */
#ifdef CDB_CLASS_IP_TRUST
#undef CDB_CLASS_IP_TRUST
#endif
#define CDB_CLASS_IP_TRUST "IP_TRUST"

/* Cdb NAME_TRUST entry in Cdb class */
#ifdef CDB_CLASS_NAME_TRUST
#undef CDB_CLASS_NAME_TRUST
#endif
#define CDB_CLASS_NAME_TRUST "NAME_TRUST"

/* Cdb HOLE_IDX entry in Cdb class */
#ifdef CDB_CLASS_HOLE_IDX
#undef CDB_CLASS_HOLE_IDX
#endif
#define CDB_CLASS_HOLE_IDX "HOLE_IDX"

/* Cdb HOLE_DAT entry in Cdb class */
#ifdef CDB_CLASS_HOLE_DAT
#undef CDB_CLASS_HOLE_DAT
#endif
#define CDB_CLASS_HOLE_DAT "HOLE_DAT"

/* Entry in /etc/services */
#ifdef CDB_ETC_SERVICE
#undef CDB_ETC_SERVICE
#endif
#define CDB_ETC_SERVICE "Cdb"

/* Environment variable for Cdb service */
#ifdef CDB_ENV_PORT
#undef CDB_ENV_PORT
#endif
#define CDB_ENV_PORT "CDB_PORT"

/* Environment variable for Cdb server host */
#ifdef CDB_ENV_HOST
#undef CDB_ENV_HOST
#endif
#define CDB_ENV_HOST "CDB_HOST"

/* Environment variable for Cdb server host */
#ifdef CDB_ENV_TIMEOUT
#undef CDB_ENV_TIMEOUT
#endif
#define CDB_ENV_TIMEOUT "CDB_TIMEOUT"

/* Environment variable for Cdb debug */
#ifdef CDB_ENV_DEBUG
#undef CDB_ENV_DEBUG
#endif
#define CDB_ENV_DEBUG "CDB_DEBUG"

/* Environment variable for Cdb rootdir */
#ifdef CDB_ENV_ROOTDIR
#undef CDB_ENV_ROOTDIR
#endif
#define CDB_ENV_ROOTDIR "CDB_ROOTDIR"

/* Environment variable for Cdb password filename */
#ifdef CDB_ENV_PWDFILENAME
#undef CDB_ENV_PWDFILENAME
#endif
#define CDB_ENV_PWDFILENAME "CDB_PWDFILENAME"

/* Environment variable for Cdb hash size */
#ifdef CDB_ENV_HASHSIZE
#undef CDB_ENV_HASHSIZE
#endif
#define CDB_ENV_HASHSIZE "CDB_HASHSIZE"

/* Environment variable for Cdb free hash size */
#ifdef CDB_ENV_FREEHASHSIZE
#undef CDB_ENV_FREEHASHSIZE
#endif
#define CDB_ENV_FREEHASHSIZE "CDB_FREEHASHSIZE"

/* Environment variable for Cdb log filename */
#ifdef CDB_ENV_LOGFILENAME
#undef CDB_ENV_LOGFILENAME
#endif
#define CDB_ENV_LOGFILENAME "CDB_LOGFILENAME"

/* Environment variable for Cdb number of threads in the pool */
#ifdef CDB_ENV_NTHREAD
#undef CDB_ENV_NTHREAD
#endif
#define CDB_ENV_NTHREAD "CDB_NTHREAD"

/* Environment variable for Cdb deadlock retry */
#ifdef CDB_ENV_DEADLOCKRETRY
#undef CDB_ENV_DEADLOCKRETRY
#endif
#define CDB_ENV_DEADLOCKRETRY "CDB_DEADLOCKRETRY"

/* Environment variable for Cdb lock deny retry */
#ifdef CDB_ENV_LOCKDENYRETRY
#undef CDB_ENV_LOCKDENYRETRY
#endif
#define CDB_ENV_LOCKDENYRETRY "CDB_LOCKDENYRETRY"

/* Environment variable for TCP_NODELAY */
#ifdef CDB_ENV_TCP_NODELAY
#undef CDB_ENV_TCP_NODELAY
#endif
#define CDB_ENV_TCP_NODELAY "CDB_TCP_NODELAY"

/* Environment variable for SO_RCVBUF */
#ifdef CDB_ENV_SO_RCVBUF
#undef CDB_ENV_SO_RCVBUF
#endif
#define CDB_ENV_SO_RCVBUF "CDB_SO_RCVBUF"

/* Environment variable for SO_SNDBUF */
#ifdef CDB_ENV_SO_SNDBUF
#undef CDB_ENV_SO_SNDBUF
#endif
#define CDB_ENV_SO_SNDBUF "CDB_SO_SNDBUF"

/* Environment variable for SO_DEBUG */
#ifdef CDB_ENV_SO_DEBUG
#undef CDB_ENV_SO_DEBUG
#endif
#define CDB_ENV_SO_DEBUG "CDB_SO_DEBUG"

/* Environment variable for TCP_RFC1323 */
#ifdef CDB_ENV_TCP_RFC1323
#undef CDB_ENV_TCP_RFC1323
#endif
#define CDB_ENV_TCP_RFC1323 "CDB_TCP_RFC1323"

/* Environment variable for TF_ACKNOW */
#ifdef CDB_ENV_TF_ACKNOW
#undef CDB_ENV_TF_ACKNOW
#endif
#define CDB_ENV_TF_ACKNOW "CDB_TF_ACKNOW"

/* Environment variable for TF2_NODELACK */
#ifdef CDB_ENV_TF2_NODELACK
#undef CDB_ENV_TF2_NODELACK
#endif
#define CDB_ENV_TF2_NODELACK "CDB_TF2_NODELACK"

/* Environment variable for TCP_FASTACK */
#ifdef CDB_ENV_TCP_FASTACK
#undef CDB_ENV_TCP_FASTACK
#endif
#define CDB_ENV_TCP_FASTACK "CDB_TCP_FASTACK"

/* Environment variable for IP_REJECT */
#ifdef CDB_ENV_IP_REJECT
#undef CDB_ENV_IP_REJECT
#endif
#define CDB_ENV_IP_REJECT "CDB_IP_REJECT"

/* Environment variable for NAME_REJECT */
#ifdef CDB_ENV_NAME_REJECT
#undef CDB_ENV_NAME_REJECT
#endif
#define CDB_ENV_NAME_REJECT "CDB_NAME_REJECT"

/* Environment variable for IP_TRUST */
#ifdef CDB_ENV_IP_TRUST
#undef CDB_ENV_IP_TRUST
#endif
#define CDB_ENV_IP_TRUST "CDB_IP_REJECT"

/* Environment variable for NAME_TRUST */
#ifdef CDB_ENV_NAME_TRUST
#undef CDB_ENV_NAME_TRUST
#endif
#define CDB_ENV_NAME_TRUST "CDB_NAME_TRUST"

/* Environment variable for HOLE_IDX */
#ifdef CDB_ENV_HOLE_IDX
#undef CDB_ENV_HOLE_IDX
#endif
#define CDB_ENV_HOLE_IDX "CDB_HOLE_IDX"

/* Environment variable for HOLE_DAT */
#ifdef CDB_ENV_HOLE_DAT
#undef CDB_ENV_HOLE_DAT
#endif
#define CDB_ENV_HOLE_DAT "CDB_HOLE_DAT"

/* ========= */
/* Functions */
/* ========= */
EXTERN_C int DLL_DECL Cdb_config_timeout _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_port _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_host _PROTO((size_t, char *));
EXTERN_C int DLL_DECL Cdb_config_debug _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_rootdir _PROTO((size_t, char *));
EXTERN_C int DLL_DECL Cdb_config_pwdfilename _PROTO((size_t, char *));
EXTERN_C int DLL_DECL Cdb_config_hashsize _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_freehashsize _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_logfilename _PROTO((size_t, char *));
EXTERN_C int DLL_DECL Cdb_config_nthread _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_deadlockretry _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_lockdenyretry _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_tcp_nodelay _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_so_sndbuf _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_so_rcvbuf _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_so_debug _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_tcp_rfc1323 _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_tf_acknow _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_tf2_nodelack _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_tcp_fastack _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_ip_reject _PROTO((size_t, char *));
EXTERN_C int DLL_DECL Cdb_config_name_reject _PROTO((size_t, char *));
EXTERN_C int DLL_DECL Cdb_config_ip_trust _PROTO((size_t, char *));
EXTERN_C int DLL_DECL Cdb_config_name_trust _PROTO((size_t, char *));
EXTERN_C int DLL_DECL Cdb_config_hole_idx _PROTO((int *));
EXTERN_C int DLL_DECL Cdb_config_hole_dat _PROTO((int *));
EXTERN_C char DLL_DECL *Cdb_config_domainname _PROTO(());
EXTERN_C char DLL_DECL *Cdb_config_domainnameorig _PROTO(());

#endif /* __Cdb_config_h */
