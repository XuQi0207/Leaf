/*
 * Copyright (C) 2000 by XuQi
 * All rights reserved
 */


/*	Cns_Data_daemon - add/replace a flie_transform_metadata associated with a file/directory */

#include <errno.h>
#include <string.h>
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
Cns_setfile_transform_metadata(const char *filename, struct Cns_filestat fst)
{
	char *actual_path;
	int c;
	char func[16];
	gid_t gid;
	int msglen;
	char *q;
	char *sbp;
	char sendbuf[REQBUFSZ];
	char server[CA_MAXHOSTNAMELEN+1];
	struct Cns_api_thread_info *thip;
	uid_t uid;

	strcpy (func, "Cns_setfile_transform_metadata");
	if (Cns_apiinit (&thip))
		return (-1);
	/*get the user info*/
	/*
	uid = geteuid();
	gid = getegid();
#if defined(_WIN32)
	if (uid < 0 || gid < 0) {
		Cns_errmsg (func, NS053);
		serrno = SENOMAPFND;
		return (-1);
	}
#endif
	*/
	if (! filename || ! (&fst)) {
		serrno = EFAULT;
		return (-1);
	}

	if (strlen (fst.path) > CA_MAXPATHLEN) {
		serrno = ENAMETOOLONG;
		return (-1);
	}

	
	if (Cns_selectsrvr (fst.path, thip->server, server, &actual_path))
		return (-1);
	
	/* Build request header */

	sbp = sendbuf;
	marshall_LONG (sbp, CNS_MAGIC);
	marshall_LONG (sbp, CNS_SETFILETRANSFORMMETADATA);
	q = sbp;        /* save pointer. The next field will be updated */
	msglen = 3 * LONGSIZE;
	marshall_LONG (sbp, msglen);

	/* Build request body */

	marshall_LONG (sbp, fst.uid);
	marshall_LONG (sbp, fst.gid);
	marshall_LONG (sbp, fst.ino);
	marshall_LONG (sbp, fst.mtime);
	marshall_LONG (sbp, fst.ctime);
	marshall_LONG (sbp, fst.atime);
	marshall_LONG (sbp, fst.nlink);
	marshall_LONG (sbp, fst.dev);
	marshall_STRING (sbp, fst.path);
	marshall_LONG (sbp, fst.filesize);
	marshall_LONG (sbp, fst.filemode);
	marshall_HYPER (sbp, thip->cwd);
	marshall_STRING (sbp, filename);
	//marshall_STRING (sbp, file_transform_metadata);

	msglen = sbp - sendbuf;
	marshall_LONG (q, msglen);	/* update length field */

	while ((c = send2nsd (NULL, server, sendbuf, msglen, NULL, 0)) &&
	    serrno == ENSNACT)
		sleep (RETRYI);
	if (c && serrno == SENAMETOOLONG) serrno = ENAMETOOLONG;
	return (c);
}
