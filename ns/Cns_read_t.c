#include <errno.h>
#include <stdlib.h>
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
#define MEMSIZE (1024*1024+10)

int Cns_read_t(const char *path, char *buff, size_t size, off_t offset, char *path_t)
{
        char *actual_path;
        int c, n;
        char func[16];
        gid_t gid;
        int msglen;
        char *q;
        char *sbp;
	char *rbp;
        char sendbuf[REQBUFSZ];
        char server[CA_MAXHOSTNAMELEN+1];
        struct Cns_api_thread_info *thip;
        uid_t uid;
//        char repbuf[1024*1024+10];
	char *repbuf=(char *)malloc(MEMSIZE);
        int res;

        strcpy (func, "Cns_read_t");
        if (Cns_apiinit (&thip)){
		free(repbuf);
                return (-1);
	}
        uid = getuid();
        gid = getgid();
#if defined(_WIN32)
        if (uid < 0 || gid < 0) {
                Cns_errmsg (func, NS053);
                serrno = SENOMAPFND;
		free(repbuf);
                return (-1);
        }
#endif

        if (! path||size<=0||offset<0||!path_t) {
                serrno = EFAULT;
		free(repbuf);
                return (-1);
        }

        if (strlen (path) > CA_MAXPATHLEN||strlen(path_t)>CA_MAXPATHLEN) {
                serrno = ENAMETOOLONG;
		free(repbuf);
                return (-1);
        }

        if (Cns_selectsrvr (path, thip->server, server, &actual_path)){
		free(repbuf);
                return (-1);
	}

        /* Build request header */

        sbp = sendbuf;
        marshall_LONG (sbp, CNS_MAGIC);
        marshall_LONG (sbp, CNS_READ_T);
        q = sbp;        /* save pointer. The next field will be updated */
        msglen = 3 * LONGSIZE;
        marshall_LONG (sbp, msglen);

        /* Build request body */

        marshall_LONG (sbp, uid);
        marshall_LONG (sbp, gid);
        marshall_HYPER (sbp, thip->cwd);
        marshall_STRING (sbp, actual_path);
	marshall_LONG (sbp, size);
        marshall_LONG (sbp, offset);
	marshall_STRING (sbp, path_t);
	
        msglen = sbp - sendbuf;
        marshall_LONG (q, msglen);      /* update length field */

        while ((c = send2nsd (NULL, server, sendbuf, msglen, repbuf, MEMSIZE)) &&
            serrno == ENSNACT)
                sleep (RETRYI);
        if (c == 0) {
                rbp = repbuf;
                unmarshall_LONG(rbp, res);
		unmarshall_STRING(rbp, buff);
        }
        if (c && serrno == SENAMETOOLONG) serrno = ENAMETOOLONG;
	free(repbuf);
        return res;
}

