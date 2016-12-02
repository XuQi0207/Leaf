/*
 * Cdb_undebug.h,v 1.4 2002/05/09 14:26:58 jdurand Exp
 */

#ifndef __Cdb_undebug_h
#define __Cdb_undebug_h

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
#define TRACE(a) { }

#ifdef DEBUG
#undef DEBUG
#endif
#define DEBUG(a) { }

#ifdef DEBUG2
#undef DEBUG2
#endif
#define DEBUG2(a) { }

#ifdef DEBUG3
#undef DEBUG3
#endif
#define DEBUG3(a) { }

#ifdef LOG
#undef LOG
#endif
#define LOG(a) { log(LOG_INFO,a); }                        /* Normal logging           */

#endif /* __Cdb_undebug_h */
