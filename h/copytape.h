/*
 * copytape.h,v 1.7 2002/06/24 09:56:31 jdurand Exp
 */

/*
 * Copyright (C) 1995-2001 by CERN/IT/PDP/DM
 * All rights reserved
 */

/*
 * @(#)copytape.h,v 1.7 2002/06/24 09:56:31 CERN IT-PDP/DM   Jean-Philippe Baud
 */

#ifndef _COPYTAPE_H
#define _COPYTAPE_H
			/* copytape constants and macros */

#include "Castor_limits.h"
#define DEFDGN "CART"	/* default device group name */
#ifdef MAXPATH
#undef MAXPATH
#endif
#define MAXPATH 80	/* maximum path length */
#define	MAXRETRY 5
#define	PRTBUFSZ 1024
#define	REPBUFSZ 1036	/* must be >= max daemon reply size */
#define	REQBUFSZ 8192	/* must be >= max daemon request size */
#define	CHECKI  10	/* max interval to check for work to be done */
#define	RETRYI	60
#define	CTPMAGIC 0x03141001
#define UPPER(s) \
	{ \
	char *q__; \
	for (q__ = s; *q__; q__++) \
		if (*q__ >= 'a' && *q__ <= 'z') *q__ = *q__ + ('A' - 'a'); \
	}
#ifndef MAXINT
#define MAXINT 0x7fffffff
#endif

			/* copytape daemon request types */

#define	TPCOPY		1
#define	CTPKILL		2
#define	CTPQRY		3

			/* copytape daemon reply types */

#define	MSG_OUT		0
#define	MSG_ERR		1
#define	STAGE_OUT	2
#define	COPYTAPERC	3
#define	UPD_VIDMAP	4

			/* -E and -T options */

#include "Ctape_constants.h"
#include "rtcp_constants.h"

			/* copytape messages */

#define	CTP00	"CTP00 - copytape daemon not available on %s\n"
#define	CTP01	"CTP01 - invalid directive: %s\n"
#define	CTP02	"CTP02 - invalid value for option %s\n"
#define	CTP03	"CTP03 - tape directives must be numbered in increasing order\n"
#define	CTP04	"CTP04 - illegal range of tapes\n"
#define	CTP05	"CTP05 - input and output tapes must be specified\n"
#define	CTP06	"CTP06 - vids must be shorter than 7 characters\n"
#define	CTP07	"CTP07 - number of tape directives does not match the value given on the mode line\n"
#define	CTP08	"CTP08 - %s : %s error : %s\n"
#define	CTP09	"CTP09 - directive line too long\n"
#define	CTP10	"CTP10 - option %s can't be global\n"
#define	CTP11	"CTP11 - parameter inconsistency with TMS for vid %s: %s<->%s\n"
#define	CTP12	"CTP12 - option %s is invalid for %s\n"
#define	CTP13	"CTP13 - trailing dash in -q option is only valid for input\n"
#define	CTP14	"CTP14 - you are not registered in account file\n"
#define	CTP15	"CTP15 - illegal function %d\n"
#define	CTP16	"CTP16 - option -k cannot be used with option -f\n"
#define	CTP17	"CTP17 - error reading request header, read = %d\n"
#define	CTP18	"CTP18 - the only supported modes are: n->n, n->1, 1->n\n"
#define	CTP19	"CTP19 - access to volume %s denied by TMS\n"
#define	CTP20	"CTP20 - invalid value %s returned by stagein for option %s\n"
#define	CTP21	"CTP21 - number of output files does not match specified value\n"
#define	CTP22	"CTP22 - option -G not allowed for user of group %s\n"
#define	CTP23	"CTP23 - invalid user: %s\n"
#define	CTP24	"CTP24 - fatal configuration error: %s %s\n"
#define	CTP25	"CTP25 - copytape host must be defined in configuration file\n"
#define	CTP26	"CTP26 - option -%c is only valid on the command line\n"
#define	CTP27	"CTP27 - syntax correct, request waiting in the queue...\n"
#if defined(_WIN32)
#define	CTP28	"CTP28 - WSAStartup unsuccessful\n"
#define	CTP29	"CTP29 - you are not registered in the unix group/passwd mapping file\n"
#define	CTP30	"CTP30 - %s error %d\n"
#endif
#define	CTP31	"CTP31 - invalid group: %d\n"
#define	CTP32	"CTP32 - %s : %s error : %s\n"
#define	CTP46	"CTP46 - request too large (max. %d)\n"
#define	CTP95	"CTP95 - Using default host %s\n"
#define	CTP96	"CTP96 - copytape not defined in services - Using default port %d\n"
#define	CTP97	"CTP97 - %s\n"
#define	CTP98	"CTP98 - %s\n"
#define	CTP99	"CTP99 - copytape returns %d\n"

			/* copy tape return codes */

#define	USERR	1	/* user error */
#define	SYERR	2	/* system error */
#define	CONFERR 4	/* configuration error */
#define	VIDMAPF	190	/* vidmap failure */
#define	REQSIGD	191	/* request signalled */
#define	CLEARED	192	/* aborted by stageclr */
#define	BLKSKPD	193	/* blocks were skipped */
#define	TPE_LSZ	194	/* blocks were skipped, stageing limited by size */
#define	MNYPARI	195	/* stagein stopped: too many tape errors, but -E keep */
#define	REQKILD	196	/* request killed by user */
#define	LIMBYSZ	197	/* limited by size */

			/* copy tape structures */
#if defined(_WIN32)
typedef long gid_t;
typedef long uid_t;
#endif

struct cptp_parm {
	int	blksize;	/* maximum block size */
	char	charconv;	/* character conversion */
	int	lrecl;		/* record length */
	int	nread;		/* number of blocks/records to be copied */
	char	recfm[CA_MAXRECFMLEN+1];	/* record format */
	char	*size;		/* size in Mbytes of data to be copied */
	char	den[CA_MAXDENLEN+1];		/* density */
	char	dgn[CA_MAXDGNLEN+1];		/* device group */
	char	fflag;		/* fid specified by user */
	int	fidsize;	/* current size of buffer allocated for fids */
	char	*fid;		/* file id */
	char	*fseq;		/* file sequence number requested by user */
	char	lbl[CA_MAXLBLTYPLEN+1];		/* label type: al, nl, sl or blp */
	int	retentd;	/* retention period in days */
	char	tapesrvr[CA_MAXHOSTNAMELEN+1];	/* tape server */
	char	E_Tflags;	/* SKIPBAD, KEEPFILE, NOTRLCHK */
	char	vid[CA_MAXVIDLEN+1];
	char	vsn[CA_MAXVSNLEN+1];
	int	actual_nbtpf;
	int	given_nbtpf;
	int	pathsize;	/* current size of buffer allocated for paths */
	char	*path;
};

struct waitq {
	struct waitq *prev;
	struct waitq *next;
	char	clienthost[CA_MAXHOSTNAMELEN+1];
	char	user[CA_MAXUSRNAMELEN+1];	/* login name */
	uid_t	uid;		/* uid or Guid */
	gid_t	gid;
	int	clientpid;
	char	inpvid1[CA_MAXVIDLEN+1];
	char	outvid1[CA_MAXVIDLEN+1];
	int	reqid;
	int	rpfd;
	int	ovl_pid;
	int	reqlen;
	char	*req_data;
	int	status;		/* -1 ==> not completed, else exit code */
};
#endif
