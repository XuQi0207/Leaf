/*
 * Copyright (C) 2008-2010 by IHEP/CC
 * All rights reserved
 * dcc.h v0.1 2008-07-03 16:50:58
 * Written by Yaodong Cheng, Computing Center, IHEP
 * Contact: Yaodong.cheng@ihep.ac.cn
 */
#ifndef _DCC_H
#define _DCC_H
#include "osdep.h"
#include "Castor_limits.h"
/* server magic */
#define DCC_MAGIC		0x120D0322
#define DCCRH_MAGIC		0x080E1301
#define DCCRR_MAGIC		0x080E1302
#define DCCMNGR_MAGIC		0x080E1303
#define DCCMIGR_MAGIC		0x080E1304
#define DCCGC_MAGIC		0x080E1304
#define DCCRH_C_MAGIC		0x080E1305	/* rh client magic */
#define	BFTRSRV_MAGIC		0x080E1306	/* bft reservation magic */
/*some request flags */
#define	DCC_LIST_BEGIN		0
#define	DCC_LIST_CONTINUE	1
#define	DCC_LIST_END		2

#define DCC_TIMEOUT		5	/* netread timeout while receiving a request */
#define DCC_C_TIMEOUT	30	/* client timeout while waiting for a reqid */
#define DCC_LISTTIMEOUT	300	/* timeout while waiting for the next sub-req */
#define DCC_CHECKDB_TIME	10 /* Time for RR to check DB automatically */
/* Request types */
#define	DCC_REQALLOC	1	/* Request to allocate disk space */
#define	DCC_RRNOTIFY	2	/* Find cartridge(s) */
#define DCC_DELREQ		3	/* Read element status */
#define	DCC_MOUNT	4	/* Mount request */
#define	DCC_UNMOUNT	5	/* Unmount request */
#define	DCC_EXPORT	6	/* Export tape request */
#define	DCC_IMPORT	7	/* Import tape request */
#define DCC_PING	8	/* Check if dccserver is alive */
#define DCC_SHUTDOWN	9	/* Shutdown the dcc server*/
#define DCC_SNDIPATH	10	/* Send ipath to client daemon*/
#define DCC_ENDLIST		11 	/* end of list operation */
#define DCC_LISTREQ		12	/* list the request */
#define DCC_UPDSTAT		13  /* update status of the request */
#define BFT_REQRSRV		14 	/* request to reserve file */

/* File request mode */
#define DCC_READ_F		1	/* read mode request */
#define DCC_WRITE_F		2 	/* write mode request */

/* File states in STAGE */
#define F_NODEFSTAT		0 	/* no defined status */
#define F_REQALLOC		1 	/* new request to allocate disk space */
#define F_WAITING_SPC	2	/* waiting for space */
#define F_WAITING_REQ	3   /* waiting for the same request by another job to complete */
#define F_STAGEIN   	4	/* currently reading from tape to disk */
#define F_STAGEOUT  	5	/* space has been reserved for stageout file */
#define F_STAGEWRT  	6	/* currently copying from disk to tape */
#define F_STAGED    	7	/* successfully staged to EOF */
#define F_STAGED_LSZ	8   /* successfully staged to specified size */
#define F_STAGED_TPE	9	/* successfully staged but blocks were skipped */
#define F_PUT_FAILED	10	/* stageput failed */
#define F_CAN_BE_MIGR	11	/* candidate for the next automatic migration (CASTOR HSM only)*/
#define F_DELAY_MIGR	12	/* candidate for the automatic migration only when its  minimum  time  before  migration will expire */
#define F_BEING_MIGR	13	/* being migrated by the automatic migrator (CASTOR HSM only)*/
#define F_WAITING_NS	14	/* waiting for creation in nameserver (CASTOR HSM only)*/
#define F_WAITING_MIGR	15	/* waiting for automatic migration request (CASTOR HSM only)*/
#define F_STAGE_FAILED	16	/* STAGE disk file failed */
#define F_ALLOC_FAILED	17	/* allocate disk file failed */
#define F_NOTIFY_FAILED	18	/* notify client failed */
#define F_ALLOCATED		19	/* disk file has been allocated successfully */


/* BFT reservation status */
#define BFT_PREREQ		20	/* prepare to reserve file */
#define BFT_REQED		21	/* request already sent */
#define BFT_BEINGMIG	22	/* being stage in file from tape */
#define	BFT_FAILED		23	/* failed to stage in file */
#define	BFT_STAGED		24	/* stage in file successfully */
#define BFT_TRSFED		25	/* already transfered to client */
#define BFT_UNKNOWN		26	/* unknown */


/* DCC server messages */
#define DCC000   "DCC000 - %s server not available on %s\n"
#define DCC001	 "DCC001 - invalid argument\n"
#define DCC002   "DCC002 - %s error : %s\n"
#define DCC003   "DCC003 - illegal function %d\n"
#define DCC004   "DCC004 - error getting request, netread = %d\n"
#define DCC005	 "DCC005 - request replier server is %s on %s\n"
#define DCC006	 "DCC006 - illegal magic %d\n"
#define DCC009   "DCC009 - fatal configuration error: %s %s\n"
#define DCC023   "DCC023 - %s is not accessible\n"
#define DCC046   "DCC046 - request too large (max. %d)\n"
#if defined(_WIN32)
#define DCC052   "DCC052 - WSAStartup unsuccessful\n"
#define DCC053   "DCC053 - you are not registered in the unix group/passwd mapping file\n"
#endif
#define DCC092   "DCC092 - %s request by %d,%d from %s\n"
#define DCC098   "DCC098 - %s\n"
#define DCC110	 "DCC110 - DB error %s\n"
#define DCC111   "DCC111 - Check new request error %s\n"
#define DCC112	 "DCC112 - user (%d, %d) not exists\n"
#define DCC113	 "DCC113 - delete request ID %s by %d,%d\n"
#define DCC114   "DCC114 - update request status error %s\n"

/* DCC server reply message */
#define	MSG_ERR		1
#define MSG_DATA	2
#define DCC_RC		3
#define	DCC_IRC		4

/* DCC port */
#define RH_PORT         8881
#define RR_PORT         8882
#define GC_PORT         8883
#define MNGR_PORT       8884
#define MIGR_PORT       8885
#define	BFT_PORT		8886

/* DCC delete flag */
#define DCC_DELID		1
#define	DCC_DELIPT		2
#define DCC_DELHSM		3

/* DCC server type */
#define DCC_RH			1	/* rh server */
#define DCC_RR			2	/* rr server */
#define DCC_MNGR		3	/* mngr server */
#define DCC_MIGR		4	/* migr server */
#define DCC_GC			5	/* gc server */
#define BFT_RSRV		6	/* BFT reservation server */

/* DCC exit code */
#define USERR     1     /* user error */
#define SYERR     2     /* system error */
#define CONFERR   4     /* configuration error */

/* Some constants */
#define DCC_OPEN_MAX		1024 	/* Maximum number of opend file */
#define CA_MAXFSNAMELEN		79		/* Maximum length of fs name, eg. /data01 */

#define DEBUGLEVEL	debuglevel()
#define UPPERCASE(a) \
{char *_c; \
  for (_c=a; *_c != '\0'; _c++)  *_c=toupper(*_c); \
}
#define UPPERCASE(a) \
{char *_c; \
  for (_c=a; *_c != '\0'; _c++)  *_c=toupper(*_c); \
}
#define LOWERCASE(a) \
{char *_c; \
  for (_c=a; *_c != '\0'; _c++)  *_c=tolower(*_c); \
}
#endif
