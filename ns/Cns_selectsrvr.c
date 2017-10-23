/*
 * Copyright (C) 2000-2003 by CERN/IT/PDP/DM
 * All rights reserved
 */

#ifndef lint
static char sccsid[] = "@(#)Cns_selectsrvr.c,v 1.7 2003/10/30 11:29:14 CERN IT-PDP/DM Jean-Philippe Baud";
#endif /* not lint */

/*	Cns_selectsrvr - select the CASTOR Name Server hostname */

/*	The following rules apply:
 *	if the path is in the form server:pathname, "server" is used else
 *	if the environment variable CNS_HOST is set, its value is used else
 *	if CNS HOST is defined in /etc/shift.conf, the value is used else
 *	the second component of path is the domain name and the third component
 *	is prefixed by the value of NsHostPfx to give the host name or its alias
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "Castor_limits.h"
#include "serrno.h"
#include "common.h"

int DLL_DECL
Cns_selectsrvr(const char *path,char *current_directory_server,char *server,char **actual_path)
{
	char buffer[CA_MAXPATHLEN+1];
	char *domain;
	char func[16];
	int n;
	char *p;
 
	strcpy (func, "Cns_selectsrvr");
	if (! path || ! server || ! actual_path) {
		serrno = EFAULT;
		return (-1);
	}

	if (*path != '/' && (p = (char *)strstr (path, ":/"))) {
		n = p - path;
		if (n > CA_MAXHOSTNAMELEN) {
			serrno = EINVAL;
			return (-1);
		}
		strncpy (server, path, n);
		*(server + n) = '\0';
		*actual_path = p + 1;
	} else {
		*actual_path = (char *) path;
		if ((p = getenv ("CNS_HOST")) || (p = getconfent ("CNS", "HOST", 0))) {
			if (strlen (p) > CA_MAXHOSTNAMELEN) {
				serrno = EINVAL;
				return (-1);
			}
			strcpy (server, p);
		} else {
			if (*path != '/') {	/* not a full path */
				if (*current_directory_server)	/* set by chdir */
					strcpy (server, current_directory_server);
				else
					server[0] = '\0';	/* use localhost */
				return (0);
			}
			strcpy (buffer, path);
			if (! strtok (buffer, "/") ||
			    (domain = strtok (NULL, "/")) == NULL ||
			    (p = strtok (NULL, "/")) == NULL) {
				server[0] = '\0';	/* use localhost */
				return (0);
			}
			if (strlen (CNSHOSTPFX) + strlen (p) + strlen (domain) +
			    1 > CA_MAXHOSTNAMELEN) {
				serrno = EINVAL;
				return (-1);
			}
			sprintf (server, "%s%s.%s", CNSHOSTPFX, p, domain);
		}
	}
	return (0);
}
