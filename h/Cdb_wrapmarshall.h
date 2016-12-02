/*
 * Cdb_wrapmarshall.h,v 1.4 2002/09/23 11:36:55 jdurand Exp
 */

#ifndef __Cdb_wrapmarshall_h
#define __Cdb_wrapmarshall_h

/* Basic macros to make sure that there is no memory overlap  */
/* This applies to _HYPER macros, in fact, and is generalized */
/* to other marshall type macros for consistency.             */

#include "marshall.h"

#ifdef wrapunmarshall_BYTE
#undef wrapunmarshall_BYTE
#endif
#define wrapunmarshall_BYTE(ptr,n) {  \
  BYTE _Cdb_byte;                     \
  unmarshall_BYTE(ptr,_Cdb_byte);     \
  n = _Cdb_byte;                      \
}

#ifdef wrapunmarshall_SHORT
#undef wrapunmarshall_SHORT
#endif
#define wrapunmarshall_SHORT(ptr,n) { \
  SHORT _Cdb_short;                   \
  unmarshall_SHORT(ptr,_Cdb_short);   \
  n = _Cdb_short;                     \
}

#ifdef wrapunmarshall_WORD
#undef wrapunmarshall_WORD
#endif
#define wrapunmarshall_WORD(ptr,n) wrapunmarshall_SHORT(ptr,n)

#ifdef wrapunmarshall_LONG
#undef wrapunmarshall_LONG
#endif
#define wrapunmarshall_LONG(ptr,n) {  \
  LONG _Cdb_long;                     \
  unmarshall_LONG(ptr,_Cdb_long);     \
  n = _Cdb_long;                      \
}

#ifdef wrapunmarshall_HYPER
#undef wrapunmarshall_HYPER
#endif
#define wrapunmarshall_HYPER(ptr,n) {  \
  HYPER _Cdb_hyper;                    \
  unmarshall_HYPER(ptr,_Cdb_hyper);    \
  n = _Cdb_hyper;                      \
}

#ifdef wrapunmarshall_STRING
#undef wrapunmarshall_STRING
#endif
#define wrapunmarshall_STRING(ptr,n) unmarshall_STRING(ptr,n)

#ifdef wrapunmarshall_STRINGN
#undef wrapunmarshall_STRINGN
#endif
#define wrapunmarshall_STRINGN(ptr,n,totalsize) unmarshall_STRINGN(ptr,n,totalsize)

#ifdef wrapunmarshall_OPAQUE
#undef wrapunmarshall_OPAQUE
#endif
#define wrapunmarshall_OPAQUE(ptr,raw,n) unmarshall_OPAQUE(ptr,raw,n)

#ifdef wrapmarshall_SHORT
#undef wrapmarshall_SHORT
#endif
#define wrapmarshall_SHORT(ptr,n) {   \
  SHORT _Cdb_short = (SHORT) n;       \
  marshall_SHORT(ptr,_Cdb_short);     \
}

#ifdef wrapmarshall_BYTE
#undef wrapmarshall_BYTE
#endif
#define wrapmarshall_BYTE(ptr,n) {    \
  BYTE _Cdb_byte = (BYTE) n;          \
  marshall_BYTE(ptr,_Cdb_byte);       \
}

#ifdef wrapmarshall_WORD
#undef wrapmarshall_WORD
#endif
#define wrapmarshall_WORD(ptr,n) wrapmarshall_SHORT(ptr,n)

#ifdef wrapmarshall_LONG
#undef wrapmarshall_LONG
#endif
#define wrapmarshall_LONG(ptr,n) {    \
  LONG _Cdb_long = (LONG) n;          \
  marshall_LONG(ptr,_Cdb_long);       \
}

#ifdef wrapmarshall_HYPER
#undef wrapmarshall_HYPER
#endif
#define wrapmarshall_HYPER(ptr,n) {   \
  HYPER _Cdb_hyper = (HYPER) n;       \
  marshall_HYPER(ptr,_Cdb_hyper);     \
}

#ifdef wrapmarshall_STRING
#undef wrapmarshall_STRING
#endif
#define wrapmarshall_STRING(ptr,n) marshall_STRING(ptr,n)

#ifdef wrapmarshall_OPAQUE
#undef wrapmarshall_OPAQUE
#endif
#define wrapmarshall_OPAQUE(ptr,raw,n) marshall_OPAQUE(ptr,raw,n)

#endif /* __Cdb_wrapmarshall_h */


