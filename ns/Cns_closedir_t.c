/*	Cns_closedir - free the Cns_DIR structure */
#include<unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#if defined(_WIN32)
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif
#include "Cns_api.h"
#include "Cns.h"
#include "marshall.h"
#include "serrno.h"

int DLL_DECL
Cns_closedir_t(Cns_DIR *dirp)
{
	int msglen;
	char *sbp;
	char sendbuf[REQBUFSZ];

	/* tell nsdaemon to free the thread */

	sbp = sendbuf;
	marshall_LONG (sbp, CNS_MAGIC);
	marshall_LONG (sbp, CNS_CLOSEDIR_T);
	msglen = 3 * LONGSIZE;
	marshall_LONG (sbp, msglen);
	while (send2nsd (&dirp->dd_fd, NULL, sendbuf, msglen, NULL, 0) &&
	    serrno == ENSNACT)
		sleep (RETRYI);

	free (dirp);
	return (0);
}
