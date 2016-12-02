/*
 * Copyright (C) 1995-2000 by CERN CN-PDP/CS
 * All rights reserved
 */

/*
 * @(#)getacct.h,v 1.1 2000/05/31 10:14:22 CERN-PDP/CS Antony Simmins
 */


#ifndef GETACCT_H
#define GETACCT_H

#define ACCOUNT_VAR	"ACCOUNT"

#define EMPTY_STR	""
#define COLON_STR	":"

#include <osdep.h>

EXTERN_C char DLL_DECL *getacct_r _PROTO((char *, size_t));
EXTERN_C char DLL_DECL *getacct _PROTO((void));

#endif /* GETACCT_H */
