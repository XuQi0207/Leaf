/*	Cns_get_Data_daemon - get the metadata associated with a file/directory */

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
Cns_get_Data_daemon(const char *path, struct Cns_filestat *filentry)
{
	char *actual_path;
	int c;
	char func[16];
	int msglen;
	char *q;
	char *rbp;
	char repbuf[5700];
	char *sbp;
	char sendbuf[REQBUFSZ];
	char server[CA_MAXHOSTNAMELEN+1];
	struct Cns_api_thread_info *thip;

	strcpy (func, "Cns_get_Data_daemon");
	if (Cns_apiinit (&thip))
		return (-1);
	
	if (! path || ! (&filentry)) {
		serrno = EFAULT;
		return (-1);
	}      
	if (Cns_selectsrvr (path, thip->server, server, &actual_path))
		return (-1);

	/* Build request header */

	sbp = sendbuf;
	marshall_LONG (sbp, CNS_MAGIC);
	marshall_LONG (sbp, CNS_GETDATADAEMON);
	q = sbp;        /* save pointer. The next field will be updated */
	msglen = 3 * LONGSIZE;
	marshall_LONG (sbp, msglen);

	/* Build request body */

        marshall_HYPER(sbp,thip->cwd);
        marshall_STRING(sbp, path);
        msglen = sbp - sendbuf;
        marshall_LONG(q, msglen);

        while((c = send2nsd (NULL, server, sendbuf, msglen, repbuf, sizeof(repbuf))) && serrno == ENSNACT)
            sleep(RETRYI);

        /* debuild request */
        if(c == 0){
	rbp =repbuf;
	unmarshall_HYPER (rbp, filentry->fileid);
	unmarshall_LONG (rbp, filentry->uid);
        unmarshall_LONG (rbp, filentry->gid);
        unmarshall_LONG (rbp, filentry->ino);
        unmarshall_TIME_T (rbp, filentry->mtime);
        unmarshall_TIME_T (rbp, filentry->ctime);
        unmarshall_TIME_T (rbp, filentry->atime);
        unmarshall_LONG (rbp, filentry->nlink);
        unmarshall_LONG (rbp, filentry->dev);
        unmarshall_HYPER (rbp, filentry->filesize);
        unmarshall_WORD (rbp, filentry->filemode);
        unmarshall_WORD (rbp, filentry->fileclass);
        unmarshall_BYTE (rbp, filentry->status);
        unmarshall_STRING (rbp, filentry->path);
        unmarshall_STRING (rbp, filentry->name);
      }
        if (c && serrno == SENAMETOOLONG) serrno = ENAMETOOLONG;
	return (c);
}
