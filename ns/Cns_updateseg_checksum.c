/*
 * Copyright (C) 2002 by CERN/IT/PDP/DM
 * All rights reserved
 */
 
#ifndef lint
static char sccsid[] = "@(#)Cns_updateseg_checksum.c,v 1.1 2004/03/03 10:57:48 CERN IT-DS/HSM Jean-Philippe Baud";
#endif /* not lint */
 
/*      Cns_updateseg_checksum - Updates the segment checksum */

#include <errno.h>
#include <sys/types.h>
#if defined(_WIN32)
#include <winsock2.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include "marshall.h"
#include "Cns_api.h"
#include "Cns.h"
#include "serrno.h"

int DLL_DECL
Cns_updateseg_checksum(char *server, u_signed64 fileid, struct Cns_segattrs *oldsegattrs, struct Cns_segattrs *newsegattrs)
{
	int c;
	char func[16];
	gid_t gid;
	int msglen;
	char *q;
	char *sbp;
	char sendbuf[REQBUFSZ];
	struct Cns_api_thread_info *thip;
	uid_t uid;

        strcpy (func, "Cns_replaceseg");
        if (Cns_apiinit (&thip))
                return (-1);
        uid = geteuid();
        gid = getegid();
#if defined(_WIN32)
        if (uid < 0 || gid < 0) {
                Cns_errmsg (func, NS053);
                serrno = SENOMAPFND;
                return (-1);
        }
#endif

	if (! oldsegattrs || ! newsegattrs) {
		serrno = EFAULT;
		return (-1);
	}

	/* Check that the members (copyno, fsec)
	   of oldsegattrs and newsegattrs are identical */

	if (oldsegattrs->copyno != newsegattrs->copyno ||
	    oldsegattrs->fsec != newsegattrs->fsec) {
		serrno = EINVAL;
		return (-1);
	}
 
	/* Build request header */

	sbp = sendbuf;
	marshall_LONG (sbp, CNS_MAGIC4);
	marshall_LONG (sbp, CNS_UPDATESEG_CHECKSUM);
	q = sbp;        /* save pointer. The next field will be updated */
	msglen = 3 * LONGSIZE;
	marshall_LONG (sbp, msglen);

	/* Build request body */
 
	marshall_LONG (sbp, uid);
	marshall_LONG (sbp, gid);
	marshall_HYPER (sbp, fileid);
	marshall_WORD (sbp, oldsegattrs->copyno);
	marshall_WORD (sbp, oldsegattrs->fsec);

	marshall_STRING (sbp, oldsegattrs->vid);
	marshall_WORD (sbp, oldsegattrs->side);
	marshall_LONG (sbp, oldsegattrs->fseq);

    marshall_STRING (sbp, newsegattrs->checksum_name);
    marshall_LONG (sbp, newsegattrs->checksum);
    
	msglen = sbp - sendbuf;
	marshall_LONG (q, msglen);	/* update length field */

	while ((c = send2nsd (NULL, server, sendbuf, msglen, NULL, 0)) &&
	    serrno == ENSNACT)
		sleep (RETRYI);
	return (c);
}
