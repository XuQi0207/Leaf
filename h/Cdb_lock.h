/*
 * Cdb_lock.h,v 1.20 2001/05/28 08:35:48 jdurand Exp
 */

#ifndef __Cdb_lock_h
#define __Cdb_lock_h

#include "Cthread_api.h" /* Needed if pthread_t is in use */

/* ============== */
/* System headers */
/* ============== */
#include <sys/types.h>      /* to get all types    */
#include <fcntl.h>          /* To get F_... values */

/* ============= */
/* Local headers */
/* ============= */
#include "osdep.h"          /* Externalization */

/* ====== */
/* Macros */
/* ====== */

/* Force use of Thread Library */
#ifndef NOCTHREAD
#ifndef USECTHREAD
#define USECTHREAD
#endif
#else
#ifdef USECTHREAD
#undef USECTHREAD
#endif
#endif

#ifdef CDB_DEBUG
#ifndef CDB_LOCK_DEBUG
#define CDB_LOCK_DEBUG 1
#endif
#endif

#ifndef CDB_LOCK_DEBUG
#define CDB_LOCK_DEBUG 0
#endif

/* Request timeout */
#ifdef  CDB_LOCK_TIMEOUT
#undef  CDB_LOCK_TIMEOUT
#endif
#define CDB_LOCK_TIMEOUT 10

/* Lifetime timeout */
#ifdef CDB_LOCK_LIFETIME
#undef CDB_LOCK_LIFETIME
#endif
#define CDB_LOCK_LIFETIME 300

/* Frequency of garbage collector */
#ifdef CDB_LOCK_GARBAGE_FREQUENCY
#undef CDB_LOCK_GARBAGE_FREQUENCY
#endif
#define CDB_LOCK_GARBAGE_FREQUENCY 300

/* Macros inspired from R.W.Stevens (APUE) for their convenience */
/* However lock implementation is done by me with threads        */

#ifdef _WIN32
/* On _WIN32 there is no F_SETLK and al. symbols. No matter. */
/* We define them right now.                                 */
#define F_SETLK 0
#define F_SETLKW 1
#define F_GETLK 2
#define F_RDLCK 3
#define F_WRLCK 4
#define F_UNLCK 5
#endif

#ifdef  read_lock
#undef  read_lock
#endif
#ifdef  readw_lock
#undef  readw_lock
#endif

#ifdef  write_lock
#undef  write_lock
#endif

#ifdef  writew_lock
#undef  writew_lock
#endif

#ifdef  un_lock
#undef  un_lock
#endif

#ifdef  isread_lock
#undef  isread_lock
#endif

#ifdef  isreadw_lock
#undef  isreadw_lock
#endif
#ifdef  iswrite_lock
#undef  iswrite_lock
#endif
#ifdef  iswritew_lock
#undef  iswritew_lock
#endif

#if CDB_LOCK_DEBUG == 1
#define read_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLK, F_RDLCK, offset, whence, len, __FILE__, __LINE__)
#define readw_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLKW, F_RDLCK, offset, whence, len, __FILE__, __LINE__)
#define write_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLK, F_WRLCK, offset, whence, len, __FILE__, __LINE__)
#define writew_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLKW, F_WRLCK, offset, whence, len, __FILE__, __LINE__)
#define un_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLK, F_UNLCK, offset, whence, len, __FILE__, __LINE__)
/* isreadw_lock is equivalent to isread_lock */
#define isread_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_GETLK, F_RDLCK, offset, whence, len, __FILE__, __LINE__)
#define isreadw_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_GETLK, F_RDLCK, offset, whence, len, __FILE__, __LINE__)
#define iswrite_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_GETLK, F_WRLCK, offset, whence, len, __FILE__, __LINE__)
/* iswritew_lock is equivalent to iswrite_lock */
#define iswritew_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_GETLK, F_WRLCK, offset, whence, len, __FILE__, __LINE__)

#else /* CDB_LOCK_DEBUG == 1 */

#define read_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLK, F_RDLCK, offset, whence, len)
#define readw_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLKW, F_RDLCK, offset, whence, len)
#define write_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLK, F_WRLCK, offset, whence, len)
#define writew_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLKW, F_WRLCK, offset, whence, len)
#define un_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_SETLK, F_UNLCK, offset, whence, len)
/* isreadw_lock is equivalent to isread_lock */
#define isread_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_GETLK, F_RDLCK, offset, whence, len)
#define isreadw_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_GETLK, F_RDLCK, offset, whence, len)
#define iswrite_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_GETLK, F_WRLCK, offset, whence, len)
/* iswritew_lock is equivalent to iswrite_lock */
#define iswritew_lock(name, fd, offset, whence, len) \
                        Cdb_lock(name, fd, F_GETLK, F_WRLCK, offset, whence, len)
#endif

EXTERN_C int DLL_DECL Cdb_lock_init _PROTO(());
#if CDB_LOCK_DEBUG == 1
EXTERN_C int DLL_DECL Cdb_lock _PROTO((int, int, int, int, off_t, int, off_t, char *, int));
#else
EXTERN_C int DLL_DECL Cdb_lock _PROTO((int, int, int, int, off_t, int, off_t));
#endif
EXTERN_C int DLL_DECL Cdb_lock_clean _PROTO((int));
EXTERN_C int DLL_DECL Cdb_lock_list _PROTO(());
#ifdef hpux
EXTERN_C int DLL_DECL Cdb_lock_open();
#else
EXTERN_C int DLL_DECL Cdb_lock_open _PROTO((int *, int *, char *, int, mode_t));
#endif
EXTERN_C char DLL_DECL *Cdb_lock_filename _PROTO((int));

#endif /* __Cdb_lock_h */

/*
 * Last Update: "Monday 28 May, 2001 at 10:35:11 CEST by Jean-Damien Durand (<A HREF=mailto:Jean-Damien.Durand@cern.ch>Jean-Damien.Durand@cern.ch</A>)"
 */
