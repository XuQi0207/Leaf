/*
 * Cdb_debug.h,v 1.7 2000/02/16 17:31:42 jdurand Exp
 */

#ifndef __Cdb_debug_h
#define __Cdb_debug_h

/* ============= */
/* Local headers */
/* ============= */
#include "log.h"

/* ====== */
/* Macros */
/* ====== */
#ifdef ARG
#undef ARG
#endif
#define ARG(X) ,X

#ifdef TRACE
#undef TRACE
#endif
#define TRACE(a) { if (Cdb_debug != 0) log(LOG_INFO,a); } /* Debugging printouts       */

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG(a) { if (Cdb_debug >= 1) log(LOG_INFO,a); } /* Debugging printouts       */

#ifdef DEBUG2
#undef DEBUG2
#endif
#define DEBUG2(a) { if (Cdb_debug >= 2) log(LOG_INFO,a); } /* Verbose debugging        */

#ifdef DEBUG3
#undef DEBUG3
#endif
#define DEBUG3(a) { if (Cdb_debug >= 3) log(LOG_INFO,a); } /* Very Verbose debugging   */

#ifdef LOG
#undef LOG
#endif
#define LOG(a) { log(LOG_INFO,a); }                        /* Normal logging           */

#endif /* __Cdb_debug_h */

/*
 * Last Update: "Wednesday 16 February, 2000 at 15:19:19 CET by Jean-Damien Durand (<A HREF=mailto:Jean-Damien.Durand@cern.ch>Jean-Damien.Durand@cern.ch</A>)"
 */

