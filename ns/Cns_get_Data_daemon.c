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
Cns_get_Data_daemon(const char *path,struct Cns_file_transform_stat *fst)
{
	char *actual_path;
	int c;
	char func[16];
	int msglen;
	char *q;
	char *rbp;
	char repbuf[CA_MAXCOMMENTLEN+1];
	char *sbp;
	char sendbuf[REQBUFSZ];
	char server[CA_MAXHOSTNAMELEN+1];
	struct Cns_api_thread_info *thip;

	strcpy (func, "Cns_get_Data_daemon");
	if (Cns_apiinit (&thip))
		return (-1);
	
	if (! path || ! (&fst)) {
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
    //    marshall_STRING(sbp, filename);

        msglen = sbp - sendbuf;
        marshall_LONG(q, msglen);

        while((c = send2nsd (NULL, server, sendbuf, msglen, repbuf, sizeof(repbuf))) &&
              serrno == ENSNACT)
            sleep(RETRYI);

        /* debuild request */
        if(c == 0){
            rbp =repbuf;
            unmarshall_LONG (rbp, fst->uid);
            unmarshall_LONG (rbp, fst->gid);
            unmarshall_LONG (rbp, fst->ino);
            unmarshall_LONG (rbp, fst->mtime);
            unmarshall_LONG (rbp, fst->ctime);
            unmarshall_LONG (rbp, fst->atime);
            unmarshall_LONG (rbp, fst->nlink);
            unmarshall_LONG (rbp, fst->dev);
            unmarshall_STRING (rbp, fst->path);
            unmarshall_LONG (rbp, fst->size);
            unmarshall_LONG (rbp, fst->mode);
            unmarshall_HYPER (rbp, thip->cwd);
	    unmarshall_STRING (rbp, fst->filena);
	    
        }
        if (c && serrno == SENAMETOOLONG) serrno = ENAMETOOLONG;
	return (c);
}
