/*
 * Cns.h,v 1.21 2004/03/03 08:50:30 bcouturi Exp
 */

/*
 * Copyright (C) 1999-2004 by CERN/IT/PDP/DM
 * All rights reserved
 */

/*
 * @(#)Cns.h,v 1.21 2004/03/03 08:50:30 CERN IT-PDP/DM Jean-Philippe Baud
 */
#ifndef _CNS_H
#define _CNS_H

			/* name server constants */
 

#include "Cns_constants.h"
#include "osdep.h"

extern char localfilepath[128];
extern int localfileid;
#define CNS_MAGIC	0x030E1301
#define CNS_MAGIC2	0x030E1302
#define CNS_MAGIC3	0x030E1303
#define CNS_MAGIC4	0x030E1304
#define CNS_DIRTIMEOUT	300	/* timeout while waiting for the next dir sub-req */
#define CNS_TIMEOUT	5	/* netread timeout while receiving a request */
#define	MAXRETRY 5
#define	RETRYI	60
#define DIRBUFSZ 4096
#define LISTBUFSZ 4096
#define LOGBUFSZ 1024
#define PRTBUFSZ  180
#define REPBUFSZ 4100	/* must be >= max name server reply size */
#define REQBUFSZ 2076	/* must be >= max name server request size */

			/* name server request types */

#define CNS_ACCESS	 0
#define CNS_CHDIR	 1
#define CNS_CHMOD	 2
#define CNS_CHOWN	 3
#define CNS_CREAT	 4
#define CNS_MKDIR	 5
#define CNS_RENAME	 6
#define CNS_RMDIR	 7
#define CNS_STAT	 8
#define CNS_UNLINK	 9
#define CNS_OPENDIR	10
#define CNS_READDIR	11
#define CNS_CLOSEDIR	12
#define CNS_OPEN	13
#define CNS_CLOSE	14
#define CNS_SETATIME	15
#define CNS_SETFSIZE	16
#define CNS_SHUTDOWN	17
#define CNS_GETSEGAT	18
#define CNS_SETSEGAT	19
#define CNS_LISTTAPE	20
#define CNS_ENDLIST	21
#define CNS_GETPATH	22
#define CNS_DELETE	23
#define CNS_UNDELETE	24
#define CNS_CHCLASS	25
#define CNS_DELCLASS	26
#define CNS_ENTCLASS	27
#define CNS_MODCLASS	28
#define CNS_QRYCLASS	29
#define CNS_LISTCLASS	30
#define CNS_DELCOMMENT	31
#define CNS_GETCOMMENT	32
#define CNS_SETCOMMENT	33
#define CNS_UTIME	34
#define CNS_REPLACESEG	35
#define CNS_UPDATESEG_CHECKSUM	36
#define CNS_SETACTUALPATH 37
#define CNS_DELACTUALPATH 38
#define CNS_GETACTUALPATH 39
#define CNS_SETFILETRANSFORMMETADATA 40
#define CNS_GETDATADAEMON 41
#define CNS_OPENDIR_T 42
#define CNS_READDIR_T 43
#define CNS_CLOSEDIR_T 44
#define CNS_CAT 45
#define CNS_SETSEG 46
#define CNS_DOWNLOAD_SEG 47
#define CNS_ACCESS_T 48
#define CNS_OPEN_T 49
#define CNS_READ_T 50
#define CNS_CREATEFILE_T 51
#define CNS_GET_VIRPATH 52
#define CNS_TOUCH_T 53
#define CNS_STAT_T 54
#define CNS_OPENDIR_T_XRD 55
#define CNS_GETATTR_ID 56

			/* name server reply types */

#define	MSG_ERR		1
#define	MSG_DATA	2
#define	CNS_RC		3
#define	CNS_IRC		4

			/* name server messages */


#define NS000	"NS000 - name server not available on %s\n"
#define	NS002	"NS002 - %s error : %s\n"
#define NS003   "NS003 - illegal function %d\n"
#define NS004   "NS004 - error getting request, netread = %d\n"
#define	NS009	"NS009 - fatal configuration error: %s %s\n"
#define	NS023	"NS023 - %s is not accessible\n"
#define NS046	"NS046 - request too large (max. %d)\n"
#if defined(_WIN32)
#define	NS052	"NS052 - WSAStartup unsuccessful\n"
#define	NS053	"NS053 - you are not registered in the unix group/passwd mapping file\n"
#endif
#define	NS092	"NS092 - %s request by %d,%d from %s\n"
#define	NS098	"NS098 - %s\n"
#endif
