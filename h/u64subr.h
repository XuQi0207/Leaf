/*
 * Copyright (C) 1999-2002 by CERN/IT/PDP/DM
 * All rights reserved
 */

/*
 * @(#)u64subr.h,v 1.5 2002/08/27 12:36:18 CERN/IT/PDP/DM Jean-Philippe Baud
 */

#ifndef __u64subr_h
#define __u64subr_h

#include "osdep.h"

EXTERN_C char * DLL_DECL i64tostr _PROTO((HYPER, char *, int));
EXTERN_C U_HYPER DLL_DECL strtou64 _PROTO((CONST char *));
EXTERN_C char * DLL_DECL u64tostr _PROTO((U_HYPER, char *, int));
EXTERN_C U_HYPER DLL_DECL strutou64 _PROTO((CONST char *));
EXTERN_C char * DLL_DECL u64tostru _PROTO((U_HYPER, char *, int));

#endif /* __u64subr_h */
