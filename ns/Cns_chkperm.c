/*
 * Copyright (C) 1999-2002 by CERN/IT/PDP/DM
 * All rights reserved
 */
 
#ifndef lint
static char sccsid[] = "@(#)Cns_chkperm.c,v 1.14 2002/10/16 06:25:39 CERN IT-PDP/DM Jean-Philippe Baud";
#endif /* not lint */
 
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#if ! defined(_WIN32)
#include <unistd.h>
#endif
#include "Cns.h"
#include "Cns_server.h"
#include "Cupv_api.h"
#include "serrno.h"
extern char localhost[CA_MAXHOSTNAMELEN+1];

/*	Cns_chkbackperm - check permissions backward */

int Cns_chkbackperm(struct Cns_dbfd *dbfd,u_signed64 fileid,int mode,uid_t uid,gid_t gid,char *clienthost)
{
	u_signed64 cur_fileid = fileid;
	struct Cns_file_metadata fmd_entry;
	char func[16];

	strcpy (func, "Cns_chkbackperm");
	while (cur_fileid != 2) {
		if (Cns_get_fmd_by_fileid (dbfd, cur_fileid, &fmd_entry, 0, NULL))
			return (-1);
		
		if ((fmd_entry.filemode & S_IFMT) != S_IFDIR) {
			serrno = ENOTDIR;
			return (-1);
		}
		if  (Cns_chkentryperm (&fmd_entry, S_IEXEC, uid, gid, clienthost))
			return (-1);
		cur_fileid = fmd_entry.parent_fileid;
	}
	return (0);
}

/*	Cns_chkdirperm - check permissions in all components of a given directory */

int Cns_chkdirperm(struct Cns_dbfd *dbfd,u_signed64 cwd,char *dir,int mode,uid_t uid,gid_t gid,char *clienthost,struct Cns_file_metadata *dir_entry,Cns_dbrec_addr *rec_addr)
{
	int c;
	char *component;
	struct Cns_file_metadata fmd_entry;
	char func[16];
	char *p;

	strcpy (func, "Cns_chkdirperm");

	/* silently remove trailing slashes */

	p = dir + strlen (dir) - 1;
	while (p > dir && *p == '/')
		*p-- = '\0';

	component = dir;
	if (*dir == '/' && *(dir+1) == '\0') {
		fmd_entry.fileid = 0;
	} else {
		fmd_entry.fileid = cwd;

		/* loop on all components of the directory name */

		for (p = dir; *p; p++) {
			if (*p != '/') continue;
			if (p != dir) {
				if (p == component) {	/* 2 consecutive slashes */
					component = p + 1;
					continue;
				}
				if (*component == '.' && p == (component + 1)) {
					component = p + 1;
					continue;
				}
				*p = '\0';
				if (strlen (component) > CA_MAXNAMELEN) {
					*p = '/';
					serrno = SENAMETOOLONG;
					return (-1);
				}
				c = Cns_get_fmd_by_fullid (dbfd, fmd_entry.fileid,
				    component, &fmd_entry, 0, NULL);
				*p = '/';
			} else
				c = Cns_get_fmd_by_fullid (dbfd, (u_signed64) 0,
				    "/", &fmd_entry, 0, NULL);
			if (c)
				return (-1);
			
			if ((fmd_entry.filemode & S_IFMT) != S_IFDIR) {
				serrno = ENOTDIR;
				return (-1);
			}
			if  (Cns_chkentryperm (&fmd_entry, S_IEXEC, uid, gid, clienthost))
				return (-1);
			component = p + 1;
		}
	}

	/* check last component of the directory name */

	if (*component && strcmp (component, ".")) {
		if (Cns_get_fmd_by_fullid (dbfd, fmd_entry.fileid, component,
		    &fmd_entry, (mode & S_IWRITE) ? 1 : 0, rec_addr))
			return (-1);
	} else {
		if (Cns_get_fmd_by_fileid (dbfd, fmd_entry.fileid,
		    &fmd_entry, (mode & S_IWRITE) ? 1 : 0, rec_addr))
			return (-1);
	}
	if ((fmd_entry.filemode & S_IFMT) != S_IFDIR) {
		serrno = ENOTDIR;
		return (-1);
	}
	if  (Cns_chkentryperm (&fmd_entry, mode, uid, gid, clienthost))
		return (-1);
	memcpy (dir_entry, &fmd_entry, sizeof(fmd_entry));
	return (0);
}

/*	Cns_chkentryperm - check permissions in a given directory component */

int Cns_chkentryperm(struct Cns_file_metadata *fmd_entry,int mode,uid_t uid,gid_t gid,char *clienthost)
{
	if (fmd_entry->uid != uid) {
		mode >>= 3;
		if (fmd_entry->gid != gid)
			mode >>= 3;
	}
	if ((fmd_entry->filemode & mode) != mode) {
		if (Cupv_check (uid, gid, clienthost, localhost, P_ADMIN))
			return (-1);
	}
	return (0);
}

/*	Cns_splitname - split a pathname into dirname and basename */
/*
 *	"/"	-->	path = "/", basename = "/"
 *	"/abc	-->	path = "/", basename = "abc"
 *	"/abc/def -->	path = "/abc", basename = "def"
 *	"abc"	-->	path = "", basename = "abc"
 */

int Cns_splitname(u_signed64 cwd,char *path,char *basename)
{
	char *p;

	if (*path == 0)  {
		serrno = ENOENT;
		return (-1);
	}

	if (! cwd && *path != '/') {
		serrno = EINVAL;
		return (-1);
	}

	/* silently remove trailing slashes */

	p = path + strlen (path) - 1;
	while (*p == '/' && p != path)
		*p = '\0';

	if ((p = strrchr (path, '/')) == NULL)
		p = path - 1;
	if (strlen (p + 1) > CA_MAXNAMELEN) {
		serrno = SENAMETOOLONG;
		return (-1);
	}
	strcpy (basename, (*(p + 1)) ? p + 1 : "/");
	if (p <= path)	/* path in the form abc or /abc */
		p++;
	*p = '\0';
	return (0);
}
