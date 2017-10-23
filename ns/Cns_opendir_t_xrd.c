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


int Cns_opendir_t_xrd(const char *path, int * child_dirid)
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
        char repbuf[CA_MAXCOMMENTLEN+1];
        int res;
	char *dirid_list=(char *)malloc(1024);
	char *pos;
	char *delims={","};
	int i=0;

        strcpy (func, "Cns_open_t_xrd");
        if (Cns_apiinit (&thip))
                return (-1);
        uid = getuid();
        gid = getgid();
#if defined(_WIN32)
        if (uid < 0 || gid < 0) {
                Cns_errmsg (func, NS053);
                serrno = SENOMAPFND;
                return (-1);
        }
#endif

        if (! path) {
                serrno = EFAULT;
                return (-1);
        }

        if (strlen (path) > CA_MAXPATHLEN) {
                serrno = ENAMETOOLONG;
                return (-1);
        }

        if (Cns_selectsrvr (path, thip->server, server, &actual_path))
                return (-1);

        /* Build request header */

        sbp = sendbuf;
        marshall_LONG (sbp, CNS_MAGIC);
        marshall_LONG (sbp, CNS_OPENDIR_T_XRD);
        q = sbp;        /* save pointer. The next field will be updated */
        msglen = 3 * LONGSIZE;
        marshall_LONG (sbp, msglen);

        /* Build request body */

        marshall_LONG (sbp, uid);
        marshall_LONG (sbp, gid);
        marshall_HYPER (sbp, thip->cwd);
        marshall_STRING (sbp, actual_path);
        msglen = sbp - sendbuf;
        marshall_LONG (q, msglen);      /* update length field */

        while ((c = send2nsd (NULL, server, sendbuf, msglen, repbuf, sizeof(repbuf))) &&
            serrno == ENSNACT)
                sleep (RETRYI);
        if (c == 0) {
                rbp = repbuf;
		unmarshall_STRING(rbp, dirid_list);
		
		pos=strtok(dirid_list, delims);
		while(pos!=NULL){
			int id=atoi(pos);
			child_dirid[i]=id;
			i++;
			pos=strtok(NULL, delims);
		}
		
        }
        if (c && serrno == SENAMETOOLONG){ 
		serrno = ENAMETOOLONG;	
	}
	free(dirid_list);
        return c;
}

