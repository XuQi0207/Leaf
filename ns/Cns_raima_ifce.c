/*
 * Copyright (C) 1999-2000 by CERN/IT/PDP/DM
 * All rights reserved
 */
 
#ifndef lint
static char sccsid[] = "@(#)Cns_raima_ifce.c,v 1.11 2000/06/29 09:00:08 CERN IT-PDP/DM Jean-Philippe Baud";
#endif /* not lint */

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include "Cns.h"
#include "cns_db.h"
#include "Cns_server.h"
#include "serrno.h"

Cns_init_dbpkg()
{
	return (0);
}

Cns_abort_tr(dbfd)
struct Cns_dbfd *dbfd;
{
	(void) d_trabort (dbfd->hSess);
	dbfd->tr_started = 0;
	return (0);
}

Cns_closedb(dbfd)
struct Cns_dbfd *dbfd;
{
	d_close (dbfd->hDb);
	s_logout (dbfd->hSess);
	return (0);
}

Cns_delete_fmd_entry(dbfd, rec_addr)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_delete_fmd_entry");
	(void) d_crset (rec_addr, dbfd->hDb);
	if ((c = d_delete (dbfd->hDb)) != S_OKAY) {
		(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
		nslogit (func, "d_delete error: %s\n", errbuf);
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_delete_smd_entry(dbfd, rec_addr)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_delete_smd_entry");
	(void) d_crset (rec_addr, dbfd->hDb);
	if ((c = d_delete (dbfd->hDb)) != S_OKAY) {
		(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
		nslogit (func, "d_delete error: %s\n", errbuf);
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_end_tr(dbfd)
struct Cns_dbfd *dbfd;
{
	(void) d_trend (dbfd->hSess);
	dbfd->tr_started = 0;
	return (0);
}

Cns_get_fmd_by_fileid(dbfd, fileid, fmd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
u_signed64 fileid;
struct Cns_file_metadata *fmd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_get_fmd_by_fileid");
        if ((c = d_keyfind (FILEID, &fileid, dbfd->hDb)) != S_OKAY) {
                if (c == S_NOTFOUND) {
			serrno = ENOENT;
		} else {
                        (void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
                        nslogit (func, "d_keyfind error: %s\n", errbuf);
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (Cns_read_fmd_entry (dbfd, fmd_entry, lock, rec_addr));
}

Cns_get_fmd_by_fullid(dbfd, parent_fileid, name, fmd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
u_signed64 parent_fileid;
char *name;
struct Cns_file_metadata *fmd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	int c;
	char errbuf[PRTBUFSZ];
	struct file_full_id full_id;
	char func[22];

	strcpy (func, "Cns_get_fmd_by_fullid");
	memcpy (&full_id.parent_fileid, &parent_fileid, sizeof(u_signed64));
        strcpy (full_id.name, name);
        if ((c = d_keyfind (FILE_FULL_ID, &full_id, dbfd->hDb)) != S_OKAY) {
                if (c == S_NOTFOUND) {
			serrno = ENOENT;
		} else {
                        (void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
                        nslogit (func, "d_keyfind error: %s\n", errbuf);
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (Cns_read_fmd_entry (dbfd, fmd_entry, lock, rec_addr));
}

Cns_get_fmd_by_pfid(dbfd, bod, parent_fileid, fmd_entry, getattr)
struct Cns_dbfd *dbfd;
int bod;
u_signed64 parent_fileid;
struct Cns_file_metadata *fmd_entry;
int getattr;
{
	int c;
	struct file_full_id full_id;
	char func[20];

	strcpy (func, "Cns_get_fmd_by_pfid");
	if (bod) {	/* just after opendir or rewinddir */
		memcpy (&full_id.parent_fileid, &parent_fileid, sizeof(u_signed64));
		c = d_pkeyfind (FILE_FULL_ID, 1, 0, &full_id, dbfd->hDb);
	} else
		c = d_pkeynext (FILE_FULL_ID, 1, 0, &full_id, dbfd->hDb);
	if (c == S_NOTFOUND)
		return (1);	/* end of directory */
	if (! getattr) {
		while (d_keyread (FILE_FULL_ID, &full_id, dbfd->hDb) == S_DELETED) {
			if (d_pkeynext (FILE_FULL_ID, 1, 0, &full_id, dbfd->hDb) == S_NOTFOUND)
				return (1);     /* end of directory */
		}
		strcpy (fmd_entry->name, full_id.name);
	} else {
		while (Cns_read_fmd_entry (dbfd, fmd_entry, 0, NULL) && serrno == ENOENT) {
			if (d_pkeynext (FILE_FULL_ID, 1, 0, &full_id, dbfd->hDb) == S_NOTFOUND)
				return (1);     /* end of directory */
		}
	}
	return (0);
}

Cns_get_max_copyno (dbfd, fileid, copyno)
struct Cns_dbfd *dbfd;
u_signed64 fileid;
int *copyno;
{
	int c;
	char errbuf[PRTBUFSZ];
	struct seg_full_id full_id;
	char func[19];
	struct Cns_seg_metadata smd_entry;

	strcpy (func, "Cns_get_max_copyno");
	if ((c = d_keylast (SEG_FULL_ID, dbfd->hDb)) != S_OKAY) {
                if (c == S_NOTFOUND) {
			serrno = ENOENT;
		} else {
                        (void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
                        nslogit (func, "d_keylast error: %s\n", errbuf);
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	memcpy (&full_id.s_fileid, &fileid, sizeof(u_signed64));
	if (d_pkeyprev (SEG_FULL_ID, 1, 0, &full_id, dbfd->hDb) == S_NOTFOUND) {
		serrno = ENOENT;
		return (-1);
	}
	while (Cns_read_smd_entry (dbfd, smd_entry, 0, NULL) &&
	    serrno == ENOENT) {
		if (d_pkeyprev (SEG_FULL_ID, 1, 0, &full_id, dbfd->hDb) == S_NOTFOUND) {
			serrno = ENOENT;
			return (-1);
	}
	*copyno = smd_entry.copyno;
	return (0);
}

Cns_get_smd_by_fullid(dbfd, fileid, copyno, fsec, smd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
u_signed64 fileid;
int copyno;
int fsec;
struct Cns_seg_metadata *smd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	int c;
	char errbuf[PRTBUFSZ];
	struct seg_full_id full_id;
	char func[22];

	strcpy (func, "Cns_get_smd_by_fullid");
	memcpy (&full_id.s_fileid, &fileid, sizeof(u_signed64));
	full_id.copyno = copyno;
	full_id.fsec = fsec;
        if ((c = d_keyfind (SEG_FULL_ID, &full_id, dbfd->hDb)) != S_OKAY) {
                if (c == S_NOTFOUND) {
			serrno = ENOENT;
		} else {
                        (void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
                        nslogit (func, "d_keyfind error: %s\n", errbuf);
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (Cns_read_smd_entry (dbfd, smd_entry, lock, rec_addr));
}

Cns_get_smd_by_pfid(dbfd, bof, fileid, smd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
int bof;
u_signed64 fileid;
struct Cns_seg_metadata *smd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	int c;
	struct seg_full_id full_id;
	char func[20];

	strcpy (func, "Cns_get_smd_by_pfid");
	if (bof) {	/* beginning of file */
		memcpy (&full_id.s_fileid, &fileid, sizeof(u_signed64));
		c = d_pkeyfind (SEG_FULL_ID, 1, 0, &full_id, dbfd->hDb);
	} else
		c = d_pkeynext (SEG_FULL_ID, 1, 0, &full_id, dbfd->hDb);
	if (c == S_NOTFOUND)
		return (1);	/* end of information for this file */
	while (Cns_read_smd_entry (dbfd, smd_entry, lock, rec_addr) &&
	    serrno == ENOENT) {
		if (d_pkeynext (SEG_FULL_ID, 1, 0, &full_id, dbfd->hDb) == S_NOTFOUND)
			return (1);     /* end of information for this file */
	}
	return (0);
}

Cns_get_smd_by_vid(dbfd, bov, vid, smd_entry)
struct Cns_dbfd *dbfd;
int bov;
char *vid;
struct Cns_seg_metadata *smd_entry;
{
	int c;
	char func[19];
	struct seg_vid_fseq vid_fseq;

	strcpy (func, "Cns_get_smd_by_vid");
	if (bov) {	/* beginning of volume */
		strcpy (vid_fseq.vid, vid);
		c = d_pkeyfind (SEG_VID_FSEQ, 1, 0, &vid_fseq, dbfd->hDb);
	} else
		c = d_pkeynext (SEG_VID_FSEQ, 1, 0, &vid_fseq, dbfd->hDb);
	if (c == S_NOTFOUND)
		return (1);	/* end of information for this volume */
	while (Cns_read_smd_entry (dbfd, smd_entry, 0, NULL) && serrno == ENOENT) {
		if (d_pkeynext (SEG_VID_FSEQ, 1, 0, &vid_fseq, dbfd->hDb) == S_NOTFOUND)
			return (1);     /* end of information for this volume */
	}
	return (0);
}

Cns_insert_fmd_entry(dbfd, fmd_entry)
struct Cns_dbfd *dbfd;
struct Cns_file_metadata *fmd_entry;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_insert_fmd_entry");
	if ((c = d_fillnew (CNS_FILE_METADATA_DB, fmd_entry, dbfd->hDb)) != S_OKAY) {
		switch (c) {
		case S_DUPLICATE:
			serrno = EEXIST;
			break;
		case S_NOSPACE:
			serrno = ENOSPC;
			break;
		default:
			serrno = SEINTERNAL;
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "db insert error: %s\n", errbuf);
		}
		return (-1);
	}
	return (0);
}

Cns_insert_smd_entry(dbfd, smd_entry)
struct Cns_dbfd *dbfd;
struct Cns_seg_metadata *smd_entry;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_insert_smd_entry");
	if ((c = d_fillnew (CNS_SEG_METADATA_DB, smd_entry, dbfd->hDb)) != S_OKAY) {
		switch (c) {
		case S_DUPLICATE:
			serrno = EEXIST;
			break;
		case S_NOSPACE:
			serrno = ENOSPC;
			break;
		default:
			serrno = SEINTERNAL;
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "db insert error: %s\n", errbuf);
		}
		return (-1);
	}
	return (0);
}

Cns_opendb(db_srvr, db_user, db_pwd, dbfd)
char *db_srvr;
char *db_user;
char *db_pwd;
struct Cns_dbfd *dbfd;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[16];
	int ntries;

	strcpy (func, "Cns_opendb");
	ntries = 0;
	while ((c = s_login (db_srvr, db_user, db_pwd, &dbfd->hSess)) == S_CATTIME &&
	    ntries++ < MAXRETRY)
		sleep (RETRYI);
	if (c) {
		nslogit (func, "db login error: %d\n", c);
		serrno = SEINTERNAL;
		return (-1);
	}
	if ((c = d_iopen ("cns_db", "s", dbfd->hSess, &dbfd->hDb)) != S_OKAY) {
		(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
		(void) s_logout (dbfd->hSess);
		nslogit (func, "db open error: %s\n", errbuf);
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_read_fmd_entry(dbfd, fmd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
struct Cns_file_metadata *fmd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_read_fmd_entry");
	c = d_crlock (lock ? "w" : "r", dbfd->hDb);
	if (c != S_OKAY && c != S_LOCKED && c != S_NOTGRANTED) {
		switch (c) {
		case S_DELETED:
			serrno = ENOENT;
			break;
		case S_UNAVAIL:
		default:
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "d_crlock error: %s\n", errbuf);
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	if (rec_addr)	/* remember record internal address for future record update */
		(void) d_crget (rec_addr, dbfd->hDb);
	if ((c = d_recread (CNS_FILE_METADATA_DB, fmd_entry, dbfd->hDb)) != S_OKAY) {
		(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
		nslogit (func, "fetch error: %s\n", errbuf);
		serrno = SEINTERNAL;
		return (-1);
	}
	if (! lock) {
		c = d_crfree (dbfd->hDb);
		if (c != S_OKAY && c != S_TRFREE) {
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "d_crfree error: %s\n", errbuf);
			serrno = SEINTERNAL;
			return (-1);
		}
	}
	return (0);
}

Cns_read_smd_entry(dbfd, smd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
struct Cns_seg_metadata *smd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_read_smd_entry");
	c = d_crlock (lock ? "w" : "r", dbfd->hDb);
	if (c != S_OKAY && c != S_LOCKED && c != S_NOTGRANTED) {
		switch (c) {
		case S_DELETED:
			serrno = ENOENT;
			break;
		case S_UNAVAIL:
		default:
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "d_crlock error: %s\n", errbuf);
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	if (rec_addr)	/* remember record internal address for future record update */
		(void) d_crget (rec_addr, dbfd->hDb);
	if ((c = d_recread (CNS_SEG_METADATA_DB, smd_entry, dbfd->hDb)) != S_OKAY) {
		(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
		nslogit (func, "fetch error: %s\n", errbuf);
		serrno = SEINTERNAL;
		return (-1);
	}
	if (! lock) {
		c = d_crfree (dbfd->hDb);
		if (c != S_OKAY && c != S_TRFREE) {
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "d_crfree error: %s\n", errbuf);
			serrno = SEINTERNAL;
			return (-1);
		}
	}
	return (0);
}

Cns_start_tr(s, dbfd)
int s;
struct Cns_dbfd *dbfd;
{
	char trid[10];

	(void) d_rdlockmodes (0, 1, dbfd->hSess);
	sprintf (trid, "%d", s);
	(void) d_trbegin (trid, dbfd->hSess);
	dbfd->tr_started = 1;
	return (0);
}

Cns_unique_id(dbfd, unique_id)
struct Cns_dbfd *dbfd;
u_signed64 *unique_id;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[16];
	struct Cns_unique_id rec;
	u_signed64 uniqueid;

	strcpy (func, "Cns_unique_id");
	if (d_recfrst (CNS_UNIQUE_ID, dbfd->hDb) == S_NOTFOUND) {
		uniqueid = 3;
		memcpy (&rec.unique_id, &uniqueid, sizeof(u_signed64));
		if ((c = d_fillnew (CNS_UNIQUE_ID, &rec, dbfd->hDb)) != S_OKAY) {
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "db insert error: %s\n", errbuf);
			serrno = SEINTERNAL;
			return (-1);
		}
	} else {
		if (c = d_crlock ("w", dbfd->hDb)) {
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "d_crlock error: %s\n", errbuf);
			serrno = SEINTERNAL;
			return (-1);
		}
		if ((c = d_recread (CNS_UNIQUE_ID, &rec, dbfd->hDb)) != S_OKAY) {
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "fetch error: %s\n", errbuf);
			serrno = SEINTERNAL;
			return (-1);
		}
		(*((u_signed64 *) &rec.unique_id))++;
		if ((c = d_recwrite (CNS_UNIQUE_ID, &rec, dbfd->hDb)) != S_OKAY) {
			(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
			nslogit (func, "store error: %s\n", errbuf);
			serrno = SEINTERNAL;
			return (-1);
		}
	}
	memcpy (unique_id, &rec.unique_id, sizeof(u_signed64));
	return (0);
}

Cns_update_fmd_entry(dbfd, rec_addr, fmd_entry)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
struct Cns_file_metadata *fmd_entry;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_update_fmd_entry");
	(void) d_crset (rec_addr, dbfd->hDb);
	if ((c = d_recwrite (CNS_FILE_METADATA_DB, fmd_entry, dbfd->hDb)) != S_OKAY) {
		(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
		nslogit (func, "db update error: %s\n", errbuf);
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_update_smd_entry(dbfd, rec_addr, smd_entry)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
struct Cns_seg_metadata *smd_entry;
{
	int c;
	char errbuf[PRTBUFSZ];
	char func[22];

	strcpy (func, "Cns_update_smd_entry");
	(void) d_crset (rec_addr, dbfd->hDb);
	if ((c = d_recwrite (CNS_SEG_METADATA_DB, smd_entry, dbfd->hDb)) != S_OKAY) {
		(void) s_errinfo (c, errbuf, PRTBUFSZ, dbfd->hSess);
		nslogit (func, "db update error: %s\n", errbuf);
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}
