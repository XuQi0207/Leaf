/*
 * Copyright (C) 1999-2000 by CERN/IT/PDP/DM
 * All rights reserved
 */
 
#ifndef lint
static char sccsid[] = "@(#)Cns_Cdb_ifce.c,v 1.24 2002/06/07 10:14:10 CERN IT-PDP/DM Jean-Philippe Baud";
#endif /* not lint */

#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include "Cdb_api.h"
#include "Cns.h"
#include "Cns_db.h"
#include "Cns_server.h"
#include "serrno.h"

Cns_init_dbpkg()
{
	return (0);
}

Cns_abort_tr(dbfd)
struct Cns_dbfd *dbfd;
{
	(void) Cdb_unlock_all (&dbfd->Cdb_sess);
	dbfd->tr_started = 0;
	return (0);
}

Cns_closedb(dbfd)
struct Cns_dbfd *dbfd;
{
	Cdb_close (&dbfd->Cdb_db);
	Cdb_logout (&dbfd->Cdb_sess);
	return (0);
}

Cns_delete_class_entry(dbfd, rec_addr)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
{
	char func[23];

	strcpy (func, "Cns_delete_class_entry");
	if (Cdb_delete (&dbfd->Cdb_db, "Cns_class_metadata_db", rec_addr)) {
		nslogit (func, "Cdb_delete error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_delete_fmd_entry(dbfd, rec_addr)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
{
	char func[21];

	strcpy (func, "Cns_delete_fmd_entry");
	if (Cdb_delete (&dbfd->Cdb_db, "Cns_file_metadata_db", rec_addr)) {
		nslogit (func, "Cdb_delete error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_delete_smd_entry(dbfd, rec_addr)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
{
	char func[21];

	strcpy (func, "Cns_delete_smd_entry");
	if (Cdb_delete (&dbfd->Cdb_db, "Cns_seg_metadata_db", rec_addr)) {
		nslogit (func, "Cdb_delete error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_delete_tppool_entry(dbfd, rec_addr)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
{
	char func[24];

	strcpy (func, "Cns_delete_tppool_entry");
	if (Cdb_delete (&dbfd->Cdb_db, "Cns_tp_pool_db", rec_addr)) {
		nslogit (func, "Cdb_delete error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_delete_umd_entry(dbfd, rec_addr)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
{
	char func[21];

	strcpy (func, "Cns_delete_umd_entry");
	if (Cdb_delete (&dbfd->Cdb_db, "Cns_user_metadata_db", rec_addr)) {
		nslogit (func, "Cdb_delete error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_end_tr(dbfd)
struct Cns_dbfd *dbfd;
{
	(void) Cdb_unlock_all (&dbfd->Cdb_sess);
	dbfd->tr_started = 0;
	return (0);
}

Cns_get_class_by_id(dbfd, classid, class_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
int classid;
struct Cns_class_metadata *class_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	char func[20];
	struct Cns_class_metadata key;

	strcpy (func, "Cns_get_class_by_id");
	key.classid = classid;
        if (Cdb_keyfind_fetch (&dbfd->Cdb_db, "Cns_class_metadata_db", "classid",
	    lock ? "w" : NULL, &key, rec_addr, class_entry)) {
                if (serrno == EDB_D_ENOENT) {
			serrno = ENOENT;
		} else {
			nslogit (func, "Cdb_keyfind error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (0);
}

Cns_get_class_by_name(dbfd, class_name, class_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
char *class_name;
struct Cns_class_metadata *class_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	char func[22];
	struct Cns_class_metadata key;

	strcpy (func, "Cns_get_class_by_name");
	strcpy (key.name, class_name);
        if (Cdb_keyfind_fetch (&dbfd->Cdb_db, "Cns_class_metadata_db", "class_name",
	    lock ? "w" : NULL, &key, rec_addr, class_entry)) {
                if (serrno == EDB_D_ENOENT) {
			serrno = ENOENT;
		} else {
			nslogit (func, "Cdb_keyfind error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (0);
}

Cns_get_fmd_by_fileid(dbfd, fileid, fmd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
u_signed64 fileid;
struct Cns_file_metadata *fmd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	char func[22];
	struct Cns_file_metadata key;

	strcpy (func, "Cns_get_fmd_by_fileid");
	key.fileid = fileid;
        if (Cdb_keyfind_fetch (&dbfd->Cdb_db, "Cns_file_metadata_db", "fileid",
	    lock ? "w" : NULL, &key, rec_addr, fmd_entry)) {
                if (serrno == EDB_D_ENOENT) {
			serrno = ENOENT;
		} else {
			nslogit (func, "Cdb_keyfind error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (0);
}

Cns_get_fmd_by_fullid(dbfd, parent_fileid, name, fmd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
u_signed64 parent_fileid;
char *name;
struct Cns_file_metadata *fmd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	char func[22];
	struct Cns_file_metadata key;

	strcpy (func, "Cns_get_fmd_by_fullid");
	key.parent_fileid = parent_fileid;
        strcpy (key.name, name);
        if (Cdb_keyfind_fetch (&dbfd->Cdb_db, "Cns_file_metadata_db", "file_full_id",
	    lock ? "w" : NULL, &key, rec_addr, fmd_entry)) {
                if (serrno == EDB_D_ENOENT) {
			serrno = ENOENT;
		} else {
			nslogit (func, "Cdb_keyfind error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (0);
}

Cns_get_fmd_by_pfid(dbfd, bod, parent_fileid, fmd_entry, getattr, endlist, dblistptr)
struct Cns_dbfd *dbfd;
int bod;
u_signed64 parent_fileid;
struct Cns_file_metadata *fmd_entry;
int getattr;
int endlist;
DBLISTPTR *dblistptr;
{
	int c;
	char func[20];
	struct Cns_file_metadata key;

	strcpy (func, "Cns_get_fmd_by_pfid");
	if (endlist)
		return (1);
	if (bod) {	/* just after opendir or rewinddir */
		key.parent_fileid = parent_fileid;
		c = Cdb_pkeyfind_fetch (&dbfd->Cdb_db, "Cns_file_metadata_db",
		    "file_full_id", 1, NULL, &key, NULL, fmd_entry);
	} else
		c = Cdb_pkeynext_fetch (&dbfd->Cdb_db, "Cns_file_metadata_db",
		    "file_full_id", 1, NULL, NULL, fmd_entry);
	if (c && serrno == EDB_D_ENOENT)
		return (1);	/* end of directory */
	if (c) {
		nslogit (func, "Cdb_pkeyxxx error: %s\n", sstrerror(serrno));
		return (-1);
	}
	return (0);
}

Cns_get_max_copyno (dbfd, fileid, copyno)
struct Cns_dbfd *dbfd;
u_signed64 fileid;
int *copyno;
{
	int found = 0;
	char func[19];
	struct Cns_seg_metadata key;
	struct Cns_seg_metadata smd_entry;

	strcpy (func, "Cns_get_max_copyno");
	key.s_fileid = fileid;
	if (Cdb_pkeyfind_fetch (&dbfd->Cdb_db, "Cns_seg_metadata_db",
	    "seg_full_id", 1, NULL, &key, NULL, &smd_entry) == 0) {
		found = 1;
		while (Cdb_pkeynext_fetch (&dbfd->Cdb_db, "Cns_seg_metadata_db",
		    "seg_full_id", 1, NULL, NULL, &smd_entry) == 0)
			found = 1;
	}
	if (! found) {
		if (serrno == EDB_D_ENOENT)
			serrno = ENOENT;
		else {
			nslogit (func, "Cdb_pkeyxxx error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
		}
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
	char func[22];
	struct Cns_seg_metadata key;

	strcpy (func, "Cns_get_smd_by_fullid");
	key.s_fileid = fileid;
	key.copyno = copyno;
	key.fsec = fsec;
        if (Cdb_keyfind_fetch (&dbfd->Cdb_db, "Cns_seg_metadata_db", "seg_full_id",
	    lock ? "w" : NULL, &key, rec_addr, smd_entry)) {
                if (serrno == EDB_D_ENOENT) {
			serrno = ENOENT;
		} else {
			nslogit (func, "Cdb_keyfind error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (0);
}

Cns_get_smd_by_pfid(dbfd, bof, fileid, smd_entry, lock, rec_addr, endlist, dblistptr)
struct Cns_dbfd *dbfd;
int bof;
u_signed64 fileid;
struct Cns_seg_metadata *smd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
int endlist;
DBLISTPTR *dblistptr;
{
	int c;
	char func[20];
	struct Cns_seg_metadata key;

	strcpy (func, "Cns_get_smd_by_pfid");
	if (endlist)
		return (1);
	if (bof) {	/* beginning of file */
		key.s_fileid = fileid;
		c = Cdb_pkeyfind_fetch (&dbfd->Cdb_db, "Cns_seg_metadata_db",
		    "seg_full_id", 1, lock ? "w" : NULL, &key, rec_addr, smd_entry);
	} else
		c = Cdb_pkeynext_fetch (&dbfd->Cdb_db, "Cns_seg_metadata_db",
		    "seg_full_id", 1, lock ? "w" : NULL, rec_addr, smd_entry);
	if (c && serrno == EDB_D_ENOENT)
		return (1);	/* end of directory */
	if (c) {
		nslogit (func, "Cdb_pkeyxxx error: %s\n", sstrerror(serrno));
		return (-1);
	}
	return (0);
}

Cns_get_smd_by_vid(dbfd, bov, vid, smd_entry, endlist, dblistptr)
struct Cns_dbfd *dbfd;
int bov;
char *vid;
struct Cns_seg_metadata *smd_entry;
int endlist;
DBLISTPTR *dblistptr;
{
	int c;
	char func[19];
	struct Cns_seg_metadata key;

	strcpy (func, "Cns_get_smd_by_vid");
	if (endlist)
		return (1);
	if (bov) {	/* beginning of volume */
		strcpy (key.vid, vid);
		c = Cdb_pkeyfind_fetch (&dbfd->Cdb_db, "Cns_seg_metadata_db",
		    "seg_vid_fseq", 1, NULL, &key, NULL, smd_entry);
	} else
		c = Cdb_pkeynext_fetch (&dbfd->Cdb_db, "Cns_seg_metadata_db",
		    "seg_vid_fseq", 1, NULL, NULL, smd_entry);
	if (c && serrno == EDB_D_ENOENT)
		return (1);	/* end of directory */
	if (c) {
		nslogit (func, "Cdb_pkeyxxx error: %s\n", sstrerror(serrno));
		return (-1);
	}
	return (0);
}

Cns_get_tppool_by_cid(dbfd, bol, classid, tppool_entry, lock, rec_addr, endlist, dblistptr)
struct Cns_dbfd *dbfd;
int bol;
int classid;
struct Cns_tp_pool *tppool_entry;
int lock;
Cns_dbrec_addr *rec_addr;
int endlist;
DBLISTPTR *dblistptr;
{
	int c;
	char func[22];
	struct Cns_tp_pool key;

	strcpy (func, "Cns_get_tppool_by_cid");
	if (endlist)
		return (1);
	if (bol) {
		key.classid = classid;
		c = Cdb_keyfind_fetch (&dbfd->Cdb_db, "Cns_tp_pool_db",
		    "classid", lock ? "w" : NULL, &key, rec_addr, tppool_entry);
	} else
		c = Cdb_keynext_fetch (&dbfd->Cdb_db, "Cns_tp_pool_db",
		    "classid", lock ? "w" : NULL, rec_addr, tppool_entry);
	if (c && serrno == EDB_D_ENOENT)
		return (1);	/* end of list */
	if (c) {
		nslogit (func, "Cdb_keyxxx error: %s\n", sstrerror(serrno));
		return (-1);
	}
	return (0);
}

Cns_get_umd_by_fileid(dbfd, fileid, umd_entry, lock, rec_addr)
struct Cns_dbfd *dbfd;
u_signed64 fileid;
struct Cns_user_metadata *umd_entry;
int lock;
Cns_dbrec_addr *rec_addr;
{
	char func[22];
	struct Cns_user_metadata key;

	strcpy (func, "Cns_get_umd_by_fileid");
	key.u_fileid = fileid;
        if (Cdb_keyfind_fetch (&dbfd->Cdb_db, "Cns_user_metadata_db", "u_fileid",
	    lock ? "w" : NULL, &key, rec_addr, umd_entry)) {
                if (serrno == EDB_D_ENOENT) {
			serrno = ENOENT;
		} else {
			nslogit (func, "Cdb_keyfind error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
                }
		return (-1);
	}
	return (0);
}

Cns_insert_class_entry(dbfd, class_entry)
struct Cns_dbfd *dbfd;
struct Cns_class_metadata *class_entry;
{
	char func[23];

	strcpy (func, "Cns_insert_class_entry");
	if (Cdb_insert (&dbfd->Cdb_db, "Cns_class_metadata_db", NULL, class_entry,
	    NULL)) {
		switch (serrno) {
		case EDB_D_UNIQUE:
			serrno = EEXIST;
			break;
		case EDB_D_NOSPC:
			serrno = ENOSPC;
			break;
		default:
			nslogit (func, "Cdb_insert error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

Cns_insert_fmd_entry(dbfd, fmd_entry)
struct Cns_dbfd *dbfd;
struct Cns_file_metadata *fmd_entry;
{
	char func[21];

	strcpy (func, "Cns_insert_fmd_entry");
	if (Cdb_insert (&dbfd->Cdb_db, "Cns_file_metadata_db", NULL, fmd_entry,
	    NULL)) {
		switch (serrno) {
		case EDB_D_UNIQUE:
			serrno = EEXIST;
			break;
		case EDB_D_NOSPC:
			serrno = ENOSPC;
			break;
		default:
			nslogit (func, "Cdb_insert error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

Cns_insert_smd_entry(dbfd, smd_entry)
struct Cns_dbfd *dbfd;
struct Cns_seg_metadata *smd_entry;
{
	char func[21];

	strcpy (func, "Cns_insert_smd_entry");
	if (Cdb_insert (&dbfd->Cdb_db, "Cns_seg_metadata_db", NULL, smd_entry,
	    NULL)) {
		switch (serrno) {
		case EDB_D_UNIQUE:
			serrno = EEXIST;
			break;
		case EDB_D_NOSPC:
			serrno = ENOSPC;
			break;
		default:
			nslogit (func, "Cdb_insert error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

Cns_insert_tppool_entry(dbfd, tppool_entry)
struct Cns_dbfd *dbfd;
struct Cns_tp_pool *tppool_entry;
{
	char func[24];

	strcpy (func, "Cns_insert_tppool_entry");
	if (Cdb_insert (&dbfd->Cdb_db, "Cns_tp_pool_db", NULL, tppool_entry,
	    NULL)) {
		switch (serrno) {
		case EDB_D_NOSPC:
			serrno = ENOSPC;
			break;
		default:
			nslogit (func, "Cdb_insert error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

Cns_insert_umd_entry(dbfd, umd_entry)
struct Cns_dbfd *dbfd;
struct Cns_user_metadata *umd_entry;
{
	char func[21];

	strcpy (func, "Cns_insert_umd_entry");
	if (Cdb_insert (&dbfd->Cdb_db, "Cns_user_metadata_db", NULL, umd_entry,
	    NULL)) {
		switch (serrno) {
		case EDB_D_UNIQUE:
			serrno = EEXIST;
			break;
		case EDB_D_NOSPC:
			serrno = ENOSPC;
			break;
		default:
			nslogit (func, "Cdb_insert error: %s\n", sstrerror(serrno));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

Cns_list_class_entry(dbfd, bol, class_entry, endlist, dblistptr)
struct Cns_dbfd *dbfd;
int bol;
struct Cns_class_metadata *class_entry;
int endlist;
DBLISTPTR *dblistptr;
{
	int c;
	char func[21];
	Cdb_off_t tbu;

	strcpy (func, "Cns_list_class_entry");
	if (endlist) {
		if (*dblistptr)
			(void) Cdb_unlock (&dbfd->Cdb_db, "Cns_class_metadata_db",
			    dblistptr);
		return (1);
	}
	if (bol) {
		c = Cdb_firstrow (&dbfd->Cdb_db, "Cns_class_metadata_db", "r",
		    dblistptr, class_entry);
	} else {
		tbu = *dblistptr;
		*dblistptr = 0;
		c = Cdb_nextrow (&dbfd->Cdb_db, "Cns_class_metadata_db", "r",
		    dblistptr, class_entry);
		(void) Cdb_unlock (&dbfd->Cdb_db, "Cns_class_metadata_db", &tbu);
	}
	if (c) {
		if (serrno == EDB_D_LISTEND)
			return (1);
		nslogit (func, "Cdb_first/nextrow error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
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
	char func[16];
	int ntries;

	strcpy (func, "Cns_opendb");
	ntries = 0;
	while ((c = Cdb_login (db_user, db_pwd, &dbfd->Cdb_sess)) &&
	    serrno == SETIMEDOUT && ntries++ < MAXRETRY)
		sleep (RETRYI);
	if (c) {
		nslogit (func, "db login error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	if (Cdb_open (&dbfd->Cdb_sess, "cns_db", &Cdb_cns_db_interface,
	    &dbfd->Cdb_db)) {
		nslogit (func, "db open error: %s\n", sstrerror(serrno));
		(void) Cdb_logout (&dbfd->Cdb_sess);
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_start_tr(s, dbfd)
int s;
struct Cns_dbfd *dbfd;
{
	dbfd->tr_started = 1;
	return (0);
}

Cns_unique_id(dbfd, unique_id)
struct Cns_dbfd *dbfd;
u_signed64 *unique_id;
{
	char func[16];

	strcpy (func, "Cns_unique_id");
	if (Cdb_uniqueid (&dbfd->Cdb_db, "Cns_file_metadata_db", 3, 1, unique_id)) {
		nslogit (func, "Cdb_uniqueid error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_update_class_entry(dbfd, rec_addr, class_entry)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
struct Cns_class_metadata *class_entry;
{
	char func[23];

	strcpy (func, "Cns_update_class_entry");
	if (Cdb_update (&dbfd->Cdb_db, "Cns_class_metadata_db", class_entry,
	    rec_addr, rec_addr)) {
		nslogit (func, "Cdb_update error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_update_fmd_entry(dbfd, rec_addr, fmd_entry)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
struct Cns_file_metadata *fmd_entry;
{
	char func[21];

	strcpy (func, "Cns_update_fmd_entry");
	if (Cdb_update (&dbfd->Cdb_db, "Cns_file_metadata_db", fmd_entry,
	    rec_addr, rec_addr)) {
		nslogit (func, "Cdb_update error: %s\n", sstrerror(serrno));
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
	char func[21];

	strcpy (func, "Cns_update_smd_entry");
	if (Cdb_update (&dbfd->Cdb_db, "Cns_seg_metadata_db", smd_entry,
	    rec_addr, rec_addr)) {
		nslogit (func, "Cdb_update error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

Cns_update_umd_entry(dbfd, rec_addr, umd_entry)
struct Cns_dbfd *dbfd;
Cns_dbrec_addr *rec_addr;
struct Cns_user_metadata *umd_entry;
{
	char func[21];

	strcpy (func, "Cns_update_umd_entry");
	if (Cdb_update (&dbfd->Cdb_db, "Cns_user_metadata_db", umd_entry,
	    rec_addr, rec_addr)) {
		nslogit (func, "Cdb_update error: %s\n", sstrerror(serrno));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

