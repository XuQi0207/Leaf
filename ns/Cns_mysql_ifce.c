/*
 * Copyright (C) 2001-2004 by CERN/IT/DS/HSM
 * All rights reserved
 */
 
#ifndef lint
static char sccsid[] = "@(#)Cns_mysql_ifce.c,v 1.7 2004/04/06 16:10:55 CERN IT-DS/HSM Jean-Philippe Baud";
#endif /* not lint */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <mysqld_error.h>
#include "Cns.h"
#include "Cns_server.h"
#include "serrno.h"
#include "u64subr.h"
#include "Cns_api.h"
#include <mysql/mysql.h> 
int Cns_init_dbpkg()
{
	int i;

	return (0);
}
int db_ping(struct Cns_dbfd *dbfd)
{
	char func[] = "db_ping";
	int ntries = 0;
	if (mysql_ping(&dbfd->mysql)) {
		nslogit(func, "mysql connect dropped");
	}
	return 0;
}

int Cns_abort_tr(struct Cns_dbfd *dbfd)
{
	mysql_ping(&dbfd->mysql);
	(void) mysql_query (&dbfd->mysql, "ROLLBACK");
	dbfd->tr_started = 0;
	return (0);
}

int Cns_closedb(struct Cns_dbfd *dbfd)
{
	mysql_close (&dbfd->mysql);
	return (0);
}

int Cns_decode_class_entry(MYSQL_ROW row,int lock,Cns_dbrec_addr *rec_addr,struct Cns_class_metadata *class_entry)
{
	int i = 0;

	if (lock)
		strcpy (*rec_addr, row[i++]);
	class_entry->classid = atoi (row[i++]);
	strcpy (class_entry->name, row[i++]);
	class_entry->uid = atoi (row[i++]);
	class_entry->gid = atoi (row[i++]);
	class_entry->min_filesize = atoi (row[i++]);
	class_entry->max_filesize = atoi (row[i++]);
	class_entry->flags = atoi (row[i++]);
	class_entry->maxdrives = atoi (row[i++]);
	class_entry->max_segsize = atoi (row[i++]);
	class_entry->migr_time_interval = atoi (row[i++]);
	class_entry->mintime_beforemigr = atoi (row[i++]);
	class_entry->nbcopies = atoi (row[i++]);
	class_entry->nbdirs_using_class = atoi (row[i++]);
	class_entry->retenp_on_disk = atoi (row[i]);
}

int Cns_decode_fmd_entry(MYSQL_ROW row,int lock,Cns_dbrec_addr *rec_addr,struct Cns_file_metadata *fmd_entry)
{
	int i = 0;

	if (lock)
		strcpy (*rec_addr, row[i++]);
	fmd_entry->fileid = strtou64 (row[i++]);
	fmd_entry->parent_fileid = strtou64 (row[i++]);
	strcpy (fmd_entry->name, row[i++]);
	fmd_entry->filemode = atoi (row[i++]);
	fmd_entry->nlink = atoi (row[i++]);
	fmd_entry->uid = atoi (row[i++]);
	fmd_entry->gid = atoi (row[i++]);
	fmd_entry->filesize = strtou64 (row[i++]);
	fmd_entry->atime = atoi (row[i++]);
	fmd_entry->mtime = atoi (row[i++]);
	fmd_entry->ctime = atoi (row[i++]);
	fmd_entry->fileclass = atoi (row[i++]);
	fmd_entry->status = *row[i];
}

int Cns_decode_smd_entry(MYSQL_ROW row,int lock,Cns_dbrec_addr *rec_addr,struct Cns_seg_metadata *smd_entry)
{
	unsigned int blockid_tmp[4];
	int i = 0;
    int j;
	if (lock)
		strcpy (*rec_addr, row[i++]);
	smd_entry->s_fileid = strtou64 (row[i++]);
	smd_entry->copyno = atoi (row[i++]);
	smd_entry->fsec = atoi (row[i++]);
	smd_entry->segsize = strtou64 (row[i++]);
	smd_entry->compression = atoi (row[i++]);
	smd_entry->s_status = *row[i++];
	strcpy (smd_entry->vid, row[i++]);
	smd_entry->side = atoi (row[i++]);
	smd_entry->fseq = atoi (row[i++]);
	sscanf (row[i], "%02x%02x%02x%02x", &blockid_tmp[0], &blockid_tmp[1],
	    &blockid_tmp[2], &blockid_tmp[3]);
	for (j = 0; j < 4; j++)
	  smd_entry->blockid[j] = blockid_tmp[j];

    /* Retrieving checksum name */
    i++;
    if (row[i] != NULL) {
        strncpy (smd_entry->checksum_name, row[i], CA_MAXCKSUMNAMELEN);
    } else {
        smd_entry->checksum_name[0] = '\0';
    }

    /* Retrieving checksum itself */
    i++;
    if (row[i] != NULL) {
        smd_entry->checksum = atoi (row[i]);
    } else {
        smd_entry->checksum = 0;
    }
}

int Cns_decode_tppool_entry(MYSQL_ROW row,int lock,Cns_dbrec_addr *rec_addr,struct Cns_tp_pool *tppool_entry)
{
	int i = 0;

	if (lock)
		strcpy (*rec_addr, row[i++]);
	tppool_entry->classid = atoi (row[i++]);
	strcpy (tppool_entry->tape_pool, row[i]);
}

int Cns_delete_class_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr)
{
	static char delete_stmt[] =
		"DELETE FROM Cns_class_metadata WHERE ROWID = %s";
	char func[23];
	char sql_stmt[70];

	strcpy (func, "Cns_delete_class_entry");
	sprintf (sql_stmt, delete_stmt, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "DELETE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_delete_fmd_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr)
{
	static char delete_stmt[] =
		"DELETE FROM Cns_file_metadata WHERE ROWID = %s";
	char func[21];
	char sql_stmt[70];

	strcpy (func, "Cns_delete_fmd_entry");
	sprintf (sql_stmt, delete_stmt, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "DELETE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_delete_smd_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr)
{
	static char delete_stmt[] =
		"DELETE FROM Cns_seg_metadata WHERE ROWID = %s";
	char func[21];
	char sql_stmt[70];

	strcpy (func, "Cns_delete_smd_entry");
	sprintf (sql_stmt, delete_stmt, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "DELETE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_delete_tppool_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr)
{
	static char delete_stmt[] =
		"DELETE FROM Cns_tp_pool WHERE ROWID = %s";
	char func[24];
	char sql_stmt[70];

	strcpy (func, "Cns_delete_tppool_entry");
	sprintf (sql_stmt, delete_stmt, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "DELETE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_delete_umd_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr)
{
	static char delete_stmt[] =
		"DELETE FROM Cns_user_metadata WHERE ROWID = %s";
	char func[21];
	char sql_stmt[70];

	strcpy (func, "Cns_delete_umd_entry");
	sprintf (sql_stmt, delete_stmt, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "DELETE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_end_tr(struct Cns_dbfd *dbfd)
{
	mysql_ping(&dbfd->mysql);
	(void) mysql_query (&dbfd->mysql, "COMMIT");
	dbfd->tr_started = 0;
	return (0);
}

int Cns_exec_query(char *func,struct Cns_dbfd *dbfd,char *sql_stmt,MYSQL_RES **res)
{
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "mysql_query error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	if ((*res = mysql_store_result (&dbfd->mysql)) == NULL) {
		nslogit (func, "mysql_store_res error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_get_class_by_id(struct Cns_dbfd *dbfd,int classid,struct Cns_class_metadata *class_entry,int lock,Cns_dbrec_addr *rec_addr)
{
	char func[20];
	static char query[] =
		"SELECT \
		 CLASSID, NAME, OWNER_UID, GID, MIN_FILESIZE, MAX_FILESIZE, \
		 FLAGS, MAXDRIVES, MAX_SEGSIZE, MIGR_TIME_INTERVAL, \
		 MINTIME_BEFOREMIGR, NBCOPIES, \
		 NBDIRS_USING_CLASS, RETENP_ON_DISK \
		FROM Cns_class_metadata \
		WHERE classid = %d";
	static char query4upd[] =
		"SELECT ROWID, \
		 CLASSID, NAME, OWNER_UID, GID, MIN_FILESIZE, MAX_FILESIZE, \
		 FLAGS, MAXDRIVES, MAX_SEGSIZE, MIGR_TIME_INTERVAL, \
		 MINTIME_BEFOREMIGR, NBCOPIES, \
		 NBDIRS_USING_CLASS, RETENP_ON_DISK \
		FROM Cns_class_metadata \
		WHERE classid = %d \
		FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_class_by_id");
	sprintf (sql_stmt, lock ? query4upd : query, classid);
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	Cns_decode_class_entry (row, lock, rec_addr, class_entry);
	mysql_free_result (res);
	return (0);
}

int Cns_get_class_by_name(struct Cns_dbfd *dbfd,char *class_name,struct Cns_class_metadata *class_entry,int lock,Cns_dbrec_addr *rec_addr)
{
	char func[22];
	static char query[] =
		"SELECT \
		 CLASSID, NAME, OWNER_UID, GID, MIN_FILESIZE, MAX_FILESIZE, \
		 FLAGS, MAXDRIVES, MAX_SEGSIZE, MIGR_TIME_INTERVAL, \
		 MINTIME_BEFOREMIGR, NBCOPIES, \
		 NBDIRS_USING_CLASS, RETENP_ON_DISK \
		FROM Cns_class_metadata \
		WHERE name = '%s'";
	static char query4upd[] =
		"SELECT ROWID, \
		 CLASSID, NAME, OWNER_UID, GID, MIN_FILESIZE, MAX_FILESIZE, \
		 FLAGS, MAXDRIVES, MAX_SEGSIZE, MIGR_TIME_INTERVAL, \
		 MINTIME_BEFOREMIGR, NBCOPIES, \
		 NBDIRS_USING_CLASS, RETENP_ON_DISK \
		FROM Cns_class_metadata \
		WHERE name = '%s' \
		FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_class_by_name");
	sprintf (sql_stmt, lock ? query4upd : query, class_name);
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	Cns_decode_class_entry (row, lock, rec_addr, class_entry);
	mysql_free_result (res);
	return (0);
}

int Cns_get_fmd_by_fileid(struct Cns_dbfd *dbfd,u_signed64 fileid,struct Cns_file_metadata *fmd_entry,int lock,Cns_dbrec_addr *rec_addr)
{
	char fileid_str[21];
	char func[22];
	static char query[] =
		"SELECT \
		 FILEID, PARENT_FILEID, NAME, FILEMODE, NLINK, OWNER_UID, GID, \
		 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS \
		FROM Cns_file_metadata \
		WHERE fileid = %s";
	static char query4upd[] =
		"SELECT ROWID, \
		 FILEID, PARENT_FILEID, NAME, FILEMODE, NLINK, OWNER_UID, GID, \
		 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS \
		FROM Cns_file_metadata \
		WHERE fileid = %s \
		FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_fmd_by_fileid");
	sprintf (sql_stmt, lock ? query4upd : query,
	    u64tostr (fileid, fileid_str, -1));
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	Cns_decode_fmd_entry (row, lock, rec_addr, fmd_entry);
	mysql_free_result (res);
	return (0);
}

int Cns_get_fmd_by_fullid(struct Cns_dbfd *dbfd,u_signed64 parent_fileid,char *name,struct Cns_file_metadata *fmd_entry,int lock,Cns_dbrec_addr *rec_addr)
{
	char escaped_name[CA_MAXNAMELEN*2+1];
	char func[22];
	char parent_fileid_str[21];
	static char query[] =
		"SELECT \
		 FILEID, PARENT_FILEID, NAME, FILEMODE, NLINK, OWNER_UID, GID, \
		 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS \
		FROM Cns_file_metadata \
		WHERE parent_fileid = %s \
		AND name = '%s'";
	static char query4upd[] =
		"SELECT ROWID, \
		 FILEID, PARENT_FILEID, NAME, FILEMODE, NLINK, OWNER_UID, GID, \
		 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS \
		FROM Cns_file_metadata \
		WHERE parent_fileid = %s \
		AND name = '%s' \
		FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_fmd_by_fullid");
	mysql_real_escape_string (&dbfd->mysql, escaped_name, name,
	    strlen (name));
	sprintf (sql_stmt, lock ? query4upd : query,
	    u64tostr (parent_fileid, parent_fileid_str, 0), escaped_name);
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	Cns_decode_fmd_entry (row, lock, rec_addr, fmd_entry);
	mysql_free_result (res);
	return (0);
}

int Cns_get_fmd_by_pfid(struct Cns_dbfd *dbfd,int bod,u_signed64 parent_fileid,struct Cns_file_metadata *fmd_entry,int getattr,int endlist,DBLISTPTR *dblistptr)
{
	char func[20];
	char parent_fileid_str[21];
	static char query[] =
		"SELECT \
		 FILEID, PARENT_FILEID, NAME, FILEMODE, NLINK, OWNER_UID, GID, \
		 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS \
		FROM Cns_file_metadata \
		WHERE parent_fileid = %s \
		ORDER BY name";
	static char query_name[] =
		"SELECT \
		 NAME \
		FROM Cns_file_metadata \
		WHERE parent_fileid = %s \
		ORDER BY name";
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_fmd_by_pfid");
	if (endlist) {
		if (*dblistptr)
			mysql_free_result (*dblistptr);
		return (1);
	}
	if (bod) {
		sprintf (sql_stmt, getattr ? query : query_name,
		    u64tostr (parent_fileid, parent_fileid_str, -1));
		if (Cns_exec_query (func, dbfd, sql_stmt, dblistptr))
			return (-1);
	}
	if ((row = mysql_fetch_row (*dblistptr)) == NULL)
		return (1);
	if (! getattr)
		strcpy (fmd_entry->name, row[0]);
	else
		Cns_decode_fmd_entry (row, 0, NULL, fmd_entry);
	return (0);
}

int Cns_get_max_copyno (struct Cns_dbfd *dbfd,u_signed64 fileid,int *copyno)
{
	char fileid_str[21];
	char func[19];
	static char query[] =
		"SELECT COPYNO \
		FROM Cns_seg_metadata \
		WHERE s_fileid = %s \
		ORDER BY copyno DESC LIMIT 1";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_max_copyno");
	sprintf (sql_stmt, query, u64tostr (fileid, fileid_str, -1));
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	*copyno = atoi (row[0]);
	mysql_free_result (res);
	return (0);
}

int Cns_get_smd_by_fullid(struct Cns_dbfd *dbfd,u_signed64 fileid,int copyno,int fsec,struct Cns_seg_metadata *smd_entry,int lock,Cns_dbrec_addr *rec_addr)
{
	char fileid_str[21];
	char func[22];
	static char query[] =
		"SELECT \
		 S_FILEID, COPYNO, FSEC, SEGSIZE, COALESCE(COMPRESSION,100), \
		 S_STATUS, VID, SIDE, FSEQ, BLOCKID, CHECKSUM_NAME, CHECKSUM \
		FROM Cns_seg_metadata \
		WHERE s_fileid = %s \
		AND copyno = %d AND fsec = %d";
	static char query4upd[] =
		"SELECT ROWID, \
		 S_FILEID, COPYNO, FSEC, SEGSIZE, COALESCE(COMPRESSION,100), \
		 S_STATUS, VID, SIDE, FSEQ, BLOCKID, CHECKSUM_NAME, CHECKSUM  \
		FROM Cns_seg_metadata \
		WHERE s_fileid = %s \
		AND copyno = %d AND fsec = %d \
		FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_smd_by_fullid");
	sprintf (sql_stmt, lock ? query4upd : query,
	    u64tostr (fileid, fileid_str, -1), copyno, fsec);
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	Cns_decode_smd_entry (row, lock, rec_addr, smd_entry);
	mysql_free_result (res);
	return (0);
}

int Cns_get_smd_by_pfid(struct Cns_dbfd *dbfd,int bof,u_signed64 fileid,struct Cns_seg_metadata *smd_entry,int lock,Cns_dbrec_addr *rec_addr,int endlist,DBLISTPTR *dblistptr)
{
	char fileid_str[21];
	char func[20];
	static char query[] =
		"SELECT \
		 S_FILEID, COPYNO, FSEC, SEGSIZE, COALESCE(COMPRESSION,100), \
		 S_STATUS, VID, SIDE, FSEQ, BLOCKID, CHECKSUM_NAME, CHECKSUM \
		FROM Cns_seg_metadata \
		WHERE s_fileid = %s \
		ORDER BY copyno, fsec";
	static char query4upd[] =
		"SELECT ROWID, \
		 S_FILEID, COPYNO, FSEC, SEGSIZE, COALESCE(COMPRESSION,100), \
		 S_STATUS, VID, SIDE, FSEQ, BLOCKID, CHECKSUM_NAME, CHECKSUM \
		FROM Cns_seg_metadata \
		WHERE s_fileid = %s \
		ORDER BY copyno, fsec \
		FOR UPDATE";
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_smd_by_pfid");
	if (endlist) {
		if (*dblistptr) {
			mysql_free_result (*dblistptr);
			*dblistptr = NULL;
		}
		return (1);
	}
	if (bof) {
		sprintf (sql_stmt, lock ? query4upd : query,
		    u64tostr (fileid, fileid_str, -1));
		if (Cns_exec_query (func, dbfd, sql_stmt, dblistptr))
			return (-1);
	}
	if ((row = mysql_fetch_row (*dblistptr)) == NULL)
		return (1);
	Cns_decode_smd_entry (row, lock, rec_addr, smd_entry);
	return (0);
}

int Cns_get_smd_by_vid(struct Cns_dbfd *dbfd,int bov,char *vid,struct Cns_seg_metadata *smd_entry,int endlist,DBLISTPTR *dblistptr)
{
	char func[19];
	static char query[] =
		"SELECT \
		 S_FILEID, COPYNO, FSEC, SEGSIZE, COALESCE(COMPRESSION,100), \
		 S_STATUS, VID, SIDE, FSEQ, BLOCKID, CHECKSUM_NAME, CHECKSUM \
		FROM Cns_seg_metadata \
		WHERE vid = '%s' \
		ORDER BY side, fseq";
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_smd_by_vid");
	if (endlist) {
		if (*dblistptr)
			mysql_free_result (*dblistptr);
		return (1);
	}
	if (bov) {
		sprintf (sql_stmt, query, vid);
		if (Cns_exec_query (func, dbfd, sql_stmt, dblistptr))
			return (-1);
	}
	if ((row = mysql_fetch_row (*dblistptr)) == NULL)
		return (1);
	Cns_decode_smd_entry (row, 0, NULL, smd_entry);
	return (0);
}

int Cns_get_tppool_by_cid(struct Cns_dbfd *dbfd,int bol,int classid,struct Cns_tp_pool *tppool_entry,int lock,Cns_dbrec_addr *rec_addr,int endlist,DBLISTPTR *dblistptr)
{
	char func[22];
	static char query[] =
		"SELECT \
		 CLASSID, TAPE_POOL \
		FROM Cns_tp_pool \
		WHERE classid = %d";
	static char query4upd[] =
		"SELECT ROWID, \
		 CLASSID, TAPE_POOL \
		FROM Cns_tp_pool \
		WHERE classid = %d \
		FOR UPDATE";
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_tppool_by_cid");
	if (endlist) {
		if (*dblistptr)
			mysql_free_result (*dblistptr);
		return (1);
	}
	if (bol) {
		sprintf (sql_stmt, lock ? query4upd : query, classid);
		if (Cns_exec_query (func, dbfd, sql_stmt, dblistptr))
			return (-1);
	}
	if ((row = mysql_fetch_row (*dblistptr)) == NULL)
		return (1);
	Cns_decode_tppool_entry (row, lock, rec_addr, tppool_entry);
	return (0);
}

int Cns_get_umd_by_fileid(struct Cns_dbfd *dbfd,u_signed64 fileid,struct Cns_user_metadata *umd_entry,int lock,Cns_dbrec_addr *rec_addr)
{
	char fileid_str[21];
	char func[22];
	static char query[] =
		"SELECT \
		 U_FILEID, COMMENTS \
		FROM Cns_user_metadata \
		WHERE u_fileid = %s";
	static char query4upd[] =
		"SELECT ROWID, \
		 U_FILEID, COMMENTS \
		FROM Cns_user_metadata \
		WHERE u_fileid = %s \
		FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_umd_by_fileid");
	sprintf (sql_stmt, lock ? query4upd : query,
	    u64tostr (fileid, fileid_str, -1));
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	if (lock)
		strcpy (*rec_addr, row[0]);
	umd_entry->u_fileid = fileid;
	strcpy (umd_entry->comments, row[lock ? 2 : 1]);
	mysql_free_result (res);
	return (0);
}

int Cns_insert_class_entry(struct Cns_dbfd *dbfd,struct Cns_class_metadata *class_entry)
{
	char func[23];
	static char insert_stmt[] =
		"INSERT INTO Cns_class_metadata \
		(CLASSID, NAME, OWNER_UID, GID, MIN_FILESIZE, MAX_FILESIZE, \
		 FLAGS, MAXDRIVES, MAX_SEGSIZE, MIGR_TIME_INTERVAL, \
		 MINTIME_BEFOREMIGR, NBCOPIES, \
		 NBDIRS_USING_CLASS, RETENP_ON_DISK) \
		VALUES \
		(%d, '%s', %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d)";
	char sql_stmt[1024];

	strcpy (func, "Cns_insert_class_entry");
	sprintf (sql_stmt, insert_stmt,
	    class_entry->classid, class_entry->name,
	    class_entry->uid, class_entry->gid,
	    class_entry->min_filesize, class_entry->max_filesize,
	    class_entry->flags, class_entry->maxdrives,
	    class_entry->max_segsize, class_entry->migr_time_interval,
	    class_entry->mintime_beforemigr, class_entry->nbcopies,
	    class_entry->nbdirs_using_class, class_entry->retenp_on_disk);
	
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
			serrno = EEXIST;
		else {
			nslogit (func, "INSERT error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

int Cns_insert_fmd_entry(struct Cns_dbfd *dbfd,struct Cns_file_metadata *fmd_entry)
{
	char escaped_name[CA_MAXNAMELEN*2+1];
	char fileid_str[21];
	char filesize_str[21];
	char func[21];
	static char insert_stmt[] =
		"INSERT INTO Cns_file_metadata \
		(FILEID, PARENT_FILEID, NAME, FILEMODE, NLINK, OWNER_UID, GID, \
		 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS, DEV, PATH, INO) \
		VALUES \
		(%s, %s, '%s', %d, %d, %d, %d, %s, %d, %d, %d, %d, '%c', %d, '%s', %d)";
	char parent_fileid_str[21];
	char sql_stmt[1024];

	strcpy (func, "Cns_insert_fmd_entry");
	mysql_real_escape_string (&dbfd->mysql, escaped_name, fmd_entry->name,
	    strlen (fmd_entry->name));
	sprintf (sql_stmt, insert_stmt,
	    u64tostr (fmd_entry->fileid, fileid_str, -1),
	    u64tostr (fmd_entry->parent_fileid, parent_fileid_str, -1),
	    escaped_name, fmd_entry->filemode, fmd_entry->nlink,
	    fmd_entry->uid, fmd_entry->gid,
	    u64tostr (fmd_entry->filesize, filesize_str, -1),
	    (int)fmd_entry->atime, (int)fmd_entry->mtime, (int)fmd_entry->ctime,
	    fmd_entry->fileclass, fmd_entry->status, fmd_entry->dev, fmd_entry->path, fmd_entry->ino);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
			serrno = EEXIST;
		else {
			nslogit (func, "INSERT error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

int Cns_insert_smd_entry(struct Cns_dbfd *dbfd,struct Cns_seg_metadata *smd_entry)
{
	char fileid_str[21];
	char func[21];
	static char insert_stmt[] =
		"INSERT INTO Cns_seg_metadata \
		(S_FILEID, COPYNO, FSEC, \
		 SEGSIZE, COMPRESSION, S_STATUS, \
		 VID, SIDE, FSEQ, BLOCKID, \
         CHECKSUM_NAME, CHECKSUM) \
		VALUES \
		(%s, %d, %d, %s, %d, '%c', '%s', %d, %d, '%02x%02x%02x%02x', '%s', %d)";
	char segsize_str[21];
	char sql_stmt[1024];

	strcpy (func, "Cns_insert_smd_entry");
	sprintf (sql_stmt, insert_stmt,
	    u64tostr (smd_entry->s_fileid, fileid_str, -1),
	    smd_entry->copyno, smd_entry->fsec,
	    u64tostr (smd_entry->segsize, segsize_str, -1),
	    smd_entry->compression, smd_entry->s_status,
	    smd_entry->vid, smd_entry->side, smd_entry->fseq,
	    smd_entry->blockid[0], smd_entry->blockid[1],
	    smd_entry->blockid[2], smd_entry->blockid[3],
        smd_entry->checksum_name, smd_entry->checksum);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
			serrno = EEXIST;
		else {
			nslogit (func, "INSERT error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

int Cns_insert_tppool_entry(struct Cns_dbfd *dbfd,struct Cns_tp_pool *tppool_entry)
{
	char func[24];
	static char insert_stmt[] =
		"INSERT INTO Cns_tp_pool \
		(CLASSID, TAPE_POOL) \
		VALUES \
		(%d, '%s')";
	char sql_stmt[1024];

	strcpy (func, "Cns_insert_tppool_entry");
	sprintf (sql_stmt, insert_stmt,
	    tppool_entry->classid, tppool_entry->tape_pool);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
			serrno = EEXIST;
		else {
			nslogit (func, "INSERT error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

int Cns_insert_umd_entry(struct Cns_dbfd *dbfd,struct Cns_user_metadata *umd_entry)
{
	char fileid_str[21];
	char func[21];
	static char insert_stmt[] =
		"INSERT INTO Cns_user_metadata \
		(U_FILEID, COMMENTS) \
		VALUES \
		(%s, '%s')";
	char sql_stmt[1024];

	strcpy (func, "Cns_insert_umd_entry");
	sprintf (sql_stmt, insert_stmt,
	    u64tostr (umd_entry->u_fileid, fileid_str, -1),
	    umd_entry->comments);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
			serrno = EEXIST;
		else {
			nslogit (func, "INSERT error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

int Cns_list_class_entry(struct Cns_dbfd *dbfd,int bol,struct Cns_class_metadata *class_entry,int endlist,DBLISTPTR *dblistptr)
{
	char func[21];
	static char query[] =
		"SELECT \
		 CLASSID, NAME, \
		 OWNER_UID, GID, \
		 MIN_FILESIZE, MAX_FILESIZE, \
		 FLAGS, MAXDRIVES, \
		 MAX_SEGSIZE, MIGR_TIME_INTERVAL, \
		 MINTIME_BEFOREMIGR, NBCOPIES, \
		 NBDIRS_USING_CLASS, RETENP_ON_DISK \
		FROM Cns_class_metadata \
		ORDER BY classid";
	MYSQL_ROW row;

	strcpy (func, "Cns_list_class_entry");
	if (endlist) {
		if (*dblistptr)
			mysql_free_result (*dblistptr);
		return (1);
	}
	if (bol) {
		if (Cns_exec_query (func, dbfd, query, dblistptr))
			return (-1);
	}
	if ((row = mysql_fetch_row (*dblistptr)) == NULL)
		return (1);
	Cns_decode_class_entry (row, 0, NULL, class_entry);
	return (0);
}

int Cns_opendb(char *db_srvr,char *db_user,char *db_pwd,struct Cns_dbfd *dbfd)
{
	char func[16];
	int ntries;
	
	char value = 1;
	strcpy (func, "Cns_opendb");
	(void) mysql_init (&dbfd->mysql);
	mysql_options(&dbfd->mysql, MYSQL_OPT_RECONNECT, (char *)&value);
	ntries = 0;
	while (1) {
		if (mysql_real_connect (&dbfd->mysql, db_srvr, db_user, db_pwd,
		    "cns_db", 0, NULL, 0)) return (0);
		if (ntries++ >= MAXRETRY) break;
		sleep (RETRYI);
	}
	nslogit (func, "CONNECT error: %s\n",
	    mysql_error (&dbfd->mysql));
	serrno = SEINTERNAL;
	return (-1);
}

int Cns_start_tr(int s,struct Cns_dbfd *dbfd)
{	
	mysql_ping(&dbfd->mysql);
	(void) mysql_query (&dbfd->mysql, "BEGIN");
	dbfd->tr_started = 1;
	return (0);
}

int Cns_unique_id(struct Cns_dbfd *dbfd,u_signed64 *unique_id)
{
	char func[16];
	static char insert_stmt[] =
		"INSERT INTO Cns_unique_id (ID) VALUES (3)";
	static char query_stmt[] =
		"SELECT ID FROM Cns_unique_id FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];
	u_signed64 uniqueid;
	char uniqueid_str[21];
	static char update_stmt[] =
		"UPDATE Cns_unique_id SET ID = %s";

	strcpy (func, "Cns_unique_id");
	mysql_ping(&dbfd->mysql);
	if (Cns_exec_query (func, dbfd, query_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		if (mysql_query (&dbfd->mysql, insert_stmt)) {
			nslogit (func, "INSERT error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
			return (-1);
		}
		*unique_id = 3;
	} else {
		uniqueid = strtou64 (row[0]) + 1;
		mysql_free_result (res);
		sprintf (sql_stmt, update_stmt, u64tostr (uniqueid, uniqueid_str, -1));
		if (mysql_query (&dbfd->mysql, sql_stmt)) {
			nslogit (func, "UPDATE error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
			return (-1);
		}
		*unique_id = uniqueid;
	}
	return (0);
}

int Cns_update_class_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr,struct Cns_class_metadata *class_entry)
{
	char func[23];
	char sql_stmt[1024];
	static char update_stmt[] =
		"UPDATE Cns_class_metadata SET \
		NAME = '%s', OWNER_UID = %d, GID = %d, MIN_FILESIZE = %d, \
		MAX_FILESIZE = %d, FLAGS = %d, MAXDRIVES = %d, \
		MAX_SEGSIZE = %d, MIGR_TIME_INTERVAL = %d, \
		MINTIME_BEFOREMIGR = %d, NBCOPIES = %d, \
		NBDIRS_USING_CLASS = %d, RETENP_ON_DISK = %d \
		WHERE ROWID = %s";

	strcpy (func, "Cns_update_class_entry");
	sprintf (sql_stmt, update_stmt,
	    class_entry->name, class_entry->uid, class_entry->gid,
	    class_entry->min_filesize, class_entry->max_filesize,
	    class_entry->flags, class_entry->maxdrives,
	    class_entry->max_segsize, class_entry->migr_time_interval,
	    class_entry->mintime_beforemigr, class_entry->nbcopies,
	    class_entry->nbdirs_using_class, class_entry->retenp_on_disk,
	    *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "UPDATE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_update_fmd_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr,struct Cns_file_metadata *fmd_entry)
{
	char escaped_name[CA_MAXNAMELEN*2+1];
	char filesize_str[21];
	char func[21];
	char parent_fileid_str[21];
	char sql_stmt[1024];
	static char update_stmt[] =
		"UPDATE Cns_file_metadata SET \
		PARENT_FILEID = %s, NAME = '%s', FILEMODE = %d, NLINK = %d, \
		OWNER_UID = %d, GID = %d, FILESIZE = %s, ATIME = %d, \
		MTIME = %d, CTIME = %d, FILECLASS = %d, STATUS = '%c' \
		WHERE ROWID = %s";

	strcpy (func, "Cns_update_fmd_entry");
	mysql_real_escape_string (&dbfd->mysql, escaped_name, fmd_entry->name,
	    strlen (fmd_entry->name));
	sprintf (sql_stmt, update_stmt,
	    u64tostr (fmd_entry->parent_fileid, parent_fileid_str, -1),
	    escaped_name, fmd_entry->filemode, fmd_entry->nlink,
	    fmd_entry->uid, fmd_entry->gid,
	    u64tostr (fmd_entry->filesize, filesize_str, -1),
	    fmd_entry->atime, fmd_entry->mtime, fmd_entry->ctime,
	    fmd_entry->fileclass, fmd_entry->status, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "UPDATE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_update_smd_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr,struct Cns_seg_metadata *smd_entry)
{
	char func[21];
	char segsize_str[21];
	char sql_stmt[1024];
	static char update_stmt[] =
		"UPDATE Cns_seg_metadata SET \
		SEGSIZE	= %s, COMPRESSION = %d, S_STATUS = '%c', \
		VID = '%s', SIDE = %d, FSEQ = %d, BLOCKID = '%02x%02x%02x%02x', \
        CHECKSUM_NAME = '%s', CHECKSUM = %d \
		WHERE ROWID = %s";

	strcpy (func, "Cns_update_smd_entry");
	sprintf (sql_stmt, update_stmt,
	    u64tostr (smd_entry->segsize, segsize_str, -1),
	    smd_entry->compression, smd_entry->s_status,
	    smd_entry->vid, smd_entry->side, smd_entry->fseq,
	    smd_entry->blockid[0], smd_entry->blockid[1],
	    smd_entry->blockid[2], smd_entry->blockid[3],
             smd_entry->checksum_name, smd_entry->checksum, 
	    *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "UPDATE error: %s\n",
                 mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_update_umd_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr,struct Cns_user_metadata *umd_entry)
{
	char func[21];
	char sql_stmt[1024];
	static char update_stmt[] =
		"UPDATE Cns_user_metadata SET \
		COMMENTS = '%s' \
		WHERE ROWID = %s";

	strcpy (func, "Cns_update_umd_entry");
	sprintf (sql_stmt, update_stmt,
	    umd_entry->comments, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "UPDATE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}


/*new founction--MIlo*/
int Cns_delete_fap_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr)
{
	static char delete_stmt[] =
		"DELETE FROM Cns_file_actualpath WHERE ROWID = %s";
	char func[21];
	char sql_stmt[70];

	strcpy (func, "Cns_delete_fap_entry");
	sprintf (sql_stmt, delete_stmt, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "DELETE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_insert_fap_entry(struct Cns_dbfd *dbfd,struct Cns_user_metadata *umd_entry)
{
	char fileid_str[21];
	char func[21];
	static char insert_stmt[] =
		"INSERT INTO Cns_file_actualpath \
		(U_FILEID, COMMENTS) \
		VALUES \
		(%s, '%s')";
	char sql_stmt[1024];

	strcpy (func, "Cns_insert_fap_entry");
	sprintf (sql_stmt, insert_stmt,
	    u64tostr (umd_entry->u_fileid, fileid_str, -1),
	    umd_entry->comments);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
			serrno = EEXIST;
		else {
			nslogit (func, "INSERT error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}

int Cns_update_fap_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr,struct Cns_user_metadata *umd_entry)
{
	char func[21];
	char sql_stmt[1024];
	static char update_stmt[] =
		"UPDATE Cns_file_actualpath SET \
		COMMENTS = '%s' \
		WHERE ROWID = %s";

	strcpy (func, "Cns_update_fap_entry");
	sprintf (sql_stmt, update_stmt,
	    umd_entry->comments, *rec_addr);
	mysql_ping(&dbfd->mysql);
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		nslogit (func, "UPDATE error: %s\n",
		    mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return (-1);
	}
	return (0);
}

int Cns_get_fap_by_fileid(struct Cns_dbfd *dbfd,u_signed64 fileid,struct Cns_user_metadata *umd_entry,int lock,Cns_dbrec_addr *rec_addr)
{
	char fileid_str[21];
	char func[22];
	static char query[] =
		"SELECT \
		 U_FILEID, COMMENTS \
		FROM Cns_file_actualpath \
		WHERE u_fileid = %s";
	static char query4upd[] =
		"SELECT ROWID, \
		 U_FILEID, COMMENTS \
		FROM Cns_file_actualpath \
		WHERE u_fileid = %s \
		FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_fap_by_fileid");
	sprintf (sql_stmt, lock ? query4upd : query,
	    u64tostr (fileid, fileid_str, -1));
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	if (lock)
		strcpy (*rec_addr, row[0]);
	umd_entry->u_fileid = fileid;
	strcpy (umd_entry->comments, row[lock ? 2 : 1]);
	mysql_free_result (res);
	return (0);
}

int Cns_decode_ftmd_entry(MYSQL_ROW row,int lock,Cns_dbrec_addr *rec_addr,struct Cns_file_metadata  *ftmd_entry)
{
	int i=0;
	if(lock)
		strcpy(*rec_addr, row[i++]);
	ftmd_entry->fileid = strtou64(row[i++]);
	ftmd_entry->parent_fileid = strtou64(row[i++]);
	strcpy(ftmd_entry->name, row[i++]);
	strcpy(ftmd_entry->path, row[i++]);
	ftmd_entry->filemode = atoi(row[i++]);
	ftmd_entry->nlink = atoi(row[i++]);
	ftmd_entry->dev = atoi(row[i++]);
	ftmd_entry->ino = atoi(row[i++]);
	ftmd_entry->uid = atoi(row[i++]);
	ftmd_entry->gid = atoi(row[i++]);
	ftmd_entry->filesize = atoi(row[i++]);
	ftmd_entry->atime = atoi(row[i++]);
	ftmd_entry->mtime = atoi(row[i++]);
	ftmd_entry->ctime = atoi(row[i++]);
	ftmd_entry->fileclass = atoi(row[i++]);
	ftmd_entry->status = *row[i++];
//	strcpy(ftmd_entry->bitmap, row[i]);
}

int Cns_get_ftmd_by_fullpath(struct Cns_dbfd *dbfd,char *path,char *name,struct Cns_file_metadata *fmd_entry,int lock,Cns_dbrec_addr *rec_addr)
{
	char escaped_name[CA_MAXNAMELEN*2+1];
	char func[22];
	char parent_fileid_str[21];
	static char query[] =
		"SELECT \
		 FILEID, PARENT_FILEID, NAME, PATH, FILEMODE, NLINK, DEV, INO, OWNER_UID, GID, \
		 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS, BITMAP \
		FROM Cns_file_transform_metadata \
		WHERE path = '%s' \
		AND name = '%s'";
	static char query4upd[] =
		"SELECT \
		FILEID, PARENT_FILEID, FILEMODE, NLINK, DEV, INO, OWNER_UID, GID, \
		FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS, BITMAP \
		FROM Cns_file_transform_metadata \
		WHERE path = '%s' \
		AND name = '%s' \
		FOR UPDATE";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_ftmd_by_fullpath");
	mysql_real_escape_string (&dbfd->mysql, escaped_name, name,
	    strlen (name));
	sprintf (sql_stmt, lock ? query4upd : query, path, escaped_name);
	if (Cns_exec_query (func, dbfd, sql_stmt, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	Cns_decode_ftmd_entry (row, lock, rec_addr, fmd_entry);
	mysql_free_result (res);
	return (0);
}
int Cns_insert_ftmd_entry(struct Cns_dbfd *dbfd,struct Cns_file_metadata *fmd_entry)
{
        char escaped_name[CA_MAXNAMELEN*2+1];
        char fileid_str[21];
        char filesize_str[21];
        char func[21];
        static char insert_stmt[] =
                "INSERT INTO Cns_file_transform_metadata \
                (FILEID, PARENT_FILEID, NAME, FILEMODE, NLINK, OWNER_UID, GID, \
                 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS, DEV, PATH, INO) \
                VALUES \
                (%s, %s, '%s', %d, %d, %d, %d, %s, %d, %d, %d, %d, '%c', %d, '%s', %d)";
        char parent_fileid_str[21];
        char sql_stmt[1024];

        strcpy (func, "Cns_insert_ftmd_entry");
        mysql_real_escape_string (&dbfd->mysql, escaped_name, fmd_entry->name,
            strlen (fmd_entry->name));
        sprintf (sql_stmt, insert_stmt,
            u64tostr (fmd_entry->fileid, fileid_str, -1),
            u64tostr (fmd_entry->parent_fileid, parent_fileid_str, -1),
            escaped_name, fmd_entry->filemode, fmd_entry->nlink,
            fmd_entry->uid, fmd_entry->gid,
            u64tostr (fmd_entry->filesize, filesize_str, -1),
            (int)fmd_entry->atime, (int)fmd_entry->mtime, (int)fmd_entry->ctime,
            fmd_entry->fileclass, fmd_entry->status, fmd_entry->dev, fmd_entry->path, fmd_entry->ino);
        mysql_ping(&dbfd->mysql);
        if (mysql_query (&dbfd->mysql, sql_stmt)) {
                if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
                        serrno = EEXIST;
                else {
                        nslogit (func, "INSERT error: %s\n",
                            mysql_error (&dbfd->mysql));
                        serrno = SEINTERNAL;
                }
                return (-1);
        }
	return 0;
}


int Cns_unique_transform_id(struct Cns_dbfd *dbfd,u_signed64 *unique_id)
{
        char func[16];
        static char insert_stmt[] =
                "INSERT INTO Cns_unique_transform_id (ID) VALUES (3)";
        static char query_stmt[] =
                "SELECT ID FROM Cns_unique_transform_id FOR UPDATE";
        MYSQL_RES *res;
        MYSQL_ROW row;
        char sql_stmt[1024];
        u_signed64 uniqueid;
        char uniqueid_str[21];
        static char update_stmt[] =
                "UPDATE Cns_unique_transform_id SET ID = %s";

        strcpy (func, "Cns_unique_transform_id");
        mysql_ping(&dbfd->mysql);
        if (Cns_exec_query (func, dbfd, query_stmt, &res))
                return (-1);
        if ((row = mysql_fetch_row (res)) == NULL) {
                mysql_free_result (res);
                if (mysql_query (&dbfd->mysql, insert_stmt)) {
                        nslogit (func, "INSERT error: %s\n",
                            mysql_error (&dbfd->mysql));
                        serrno = SEINTERNAL;
                        return (-1);
                }
                *unique_id = 3;
        } else {
                uniqueid = strtou64 (row[0]) + 1;
                mysql_free_result (res);
                sprintf (sql_stmt, update_stmt, u64tostr (uniqueid, uniqueid_str, -1));
                if (mysql_query (&dbfd->mysql, sql_stmt)) {
                        nslogit (func, "UPDATE error: %s\n",
                            mysql_error (&dbfd->mysql));
                        serrno = SEINTERNAL;
                        return (-1);
                }
                *unique_id = uniqueid;
        }
        return (0);
}

int Cns_get_ftmd_by_pfid(struct Cns_dbfd *dbfd,int bod,u_signed64 parent_fileid,struct Cns_file_metadata *fmd_entry,int getattr,int endlist,DBLISTPTR *dblistptr)
{
	char func[20];
	char parent_fileid_str[21];
	static char query[] =
		"SELECT \
		 FILEID, PARENT_FILEID, NAME, PATH, FILEMODE, NLINK, DEV, INO, OWNER_UID, GID, \
		 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS \
		FROM Cns_file_transform_metadata \
		WHERE parent_fileid = %s \
		ORDER BY name";
	static char query_name[] =
		"SELECT \
		 NAME \
		FROM Cns_file_transform_metadata \
		WHERE parent_fileid = %s \
		ORDER BY name";
	MYSQL_ROW row;
	char sql_stmt[1024];

	strcpy (func, "Cns_get_fmd_by_pfid");
	if (endlist) {
		if (*dblistptr)
			mysql_free_result (*dblistptr);
		return (1);
	}
	if (bod) {
		sprintf (sql_stmt, getattr ? query : query_name,
		    u64tostr (parent_fileid, parent_fileid_str, -1));
		if (Cns_exec_query (func, dbfd, sql_stmt, dblistptr))
			return (-1);
	}
	if ((row = mysql_fetch_row (*dblistptr)) == NULL)
		return (1);
	if (! getattr)
		strcpy (fmd_entry->name, row[0]);
	else
		Cns_decode_ftmd_entry (row, 0, NULL, fmd_entry);
	return (0);
}


int Cns_update_ftmd_entry(struct Cns_dbfd *dbfd,Cns_dbrec_addr *rec_addr,struct Cns_file_metadata *fmd_entry)
{
        char escaped_name[CA_MAXNAMELEN*2+1];
        char filesize_str[21];
        char func[21];
        char parent_fileid_str[21];
        char sql_stmt[1024];
        static char update_stmt[] =
                "UPDATE Cns_file_transform_metadata SET \
                 FILEMODE = %d, NLINK = %d, DEV = %d, INO = %d,\
                OWNER_UID = %d, GID = %d, FILESIZE = %s, ATIME = %d, \
                MTIME = %d, CTIME = %d, FILECLASS = %d, STATUS = '%c' \
                WHERE FILEID = %d";

        strcpy (func, "Cns_update_ftmd_entry");
        mysql_real_escape_string (&dbfd->mysql, escaped_name, fmd_entry->name,
            strlen (fmd_entry->name));
        sprintf (sql_stmt, update_stmt,
            fmd_entry->filemode, fmd_entry->nlink,fmd_entry->dev,fmd_entry->ino, 
            fmd_entry->uid, fmd_entry->gid,
            u64tostr (fmd_entry->filesize, filesize_str, -1),
            fmd_entry->atime, fmd_entry->mtime, fmd_entry->ctime,
            fmd_entry->fileclass, fmd_entry->status, fmd_entry->fileid);
        mysql_ping(&dbfd->mysql);
        if (mysql_query (&dbfd->mysql, sql_stmt)) {
                nslogit (func, "UPDATE error: %s\n",
                    mysql_error (&dbfd->mysql));
                serrno = SEINTERNAL;
                return (-1);
        }
        return (0);
}
int Cns_get_t_filemeta(struct Cns_dbfd *dbfd,char *path,char *basename,int *fd,int *filesize,int *mode)
{
	char func[22];
	static char query[] =
		"SELECT \
		 FILEID, FILESIZE, FILEMODE \
		FROM Cns_file_transform_metadata \
		WHERE name ='%s' and path= '%s'";
	MYSQL_RES *res;
	MYSQL_ROW row;
	char sql_stmt[1024];
	strcpy (func, "Cns_cat_by_path");
	*fd=-1;
	sprintf (sql_stmt, query, basename, path);

        if (mysql_query (&dbfd->mysql, sql_stmt)) {
                if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
                        serrno = EEXIST;
                else {
                        nslogit (func, "SELECT error: %s\n",
                            mysql_error (&dbfd->mysql));
                        serrno = SEINTERNAL;
                }
                return (-1);
        }
        if((res=mysql_store_result(&dbfd->mysql))==NULL)
        {
                nslogit (func, "mysql_store_res error: %s\n",
                mysql_error (&dbfd->mysql));
                serrno = SEINTERNAL;
                return -1;
        }

	
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	sscanf(row[0],"%d",fd);
	sscanf(row[1],"%d",filesize);
	sscanf(row[2],"%d",mode);
	mysql_free_result (res);
	return (0);
}
int Cns_get_t_filepath(struct Cns_dbfd *dbfd,int fd,char *actual_path)
{
	char func[22];
        static char query[]="SELECT PATH FROM Cns_seg_transform_metadata WHERE FD = %d";
        MYSQL_RES *res;
        MYSQL_ROW row;
        char sql_stmt[1024];
        strcpy (func, "Cns_cat_by_path");
        sprintf(sql_stmt, query, fd);

        if (mysql_query (&dbfd->mysql, sql_stmt)) {
                if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
                        serrno = EEXIST;
                else {
                        nslogit (func, "INSERT error: %s\n",
                            mysql_error (&dbfd->mysql));
                        serrno = SEINTERNAL;
                }
                return (-1);
        }
        if((res=mysql_store_result(&dbfd->mysql))==NULL)
	{
		nslogit (func, "mysql_store_res error: %s\n",
		mysql_error (&dbfd->mysql));
		serrno = SEINTERNAL;
		return -1;
	}
	if ((row = mysql_fetch_row (res)) == NULL) {
                strcpy(actual_path,"FDNDY");
        }else
                strcpy(actual_path,row[0]);
        mysql_free_result (res);
	return 0;
}
int Cns_set_t_segmeta(struct Cns_dbfd *dbfd,char *path,char *basename,int fd,int size,char *physic_path)
{
	char func[21];
	static char insert_stmt[]=
		"INSERT INTO Cns_seg_transform_metadata\
		(FD, seg_size, path)\
		VALUES\
		( %d, %d, '%s')";
	char sql_stmt[1024];
	strcpy(func,"Cns_set_segmetadata");
	sprintf(sql_stmt,insert_stmt,fd,size,physic_path);
	if(mysql_ping(&dbfd->mysql)!=0){
		printf("sql_connect down\n ");
	}
	if (mysql_query (&dbfd->mysql, sql_stmt)) {
		if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
			serrno = EEXIST;
		else {
			nslogit (func, "INSERT error: %s\n",
			    mysql_error (&dbfd->mysql));
			serrno = SEINTERNAL;
		}
		return (-1);
	}
	return (0);
}
int Cns_set_t_filebitmap(struct Cns_dbfd *dbfd,char *path,char *basename,char* bitmap)
{
        char func[21];
        static char insert_stmt[]=
                "UPDATE Cns_file_transform_metadata\
                SET bitmap='%s'\
                WHERE path='%s' AND name='%s'";
        char sql_stmt[1024];
        strcpy(func,"Cns_set_segmetadata");
        sprintf(sql_stmt,insert_stmt,bitmap,path,basename);
        if(mysql_ping(&dbfd->mysql)!=0){
                printf("sql_connect down\n ");
        }
        if (mysql_query (&dbfd->mysql, sql_stmt)) {
                if (mysql_errno (&dbfd->mysql) == ER_DUP_ENTRY)
                        serrno = EEXIST;
                else {
                        nslogit (func, "INSERT error: %s\n",
                            mysql_error (&dbfd->mysql));
                        serrno = SEINTERNAL;
                }
                return (-1);
        }
        return (0);

}

int Cns_get_bitmap(struct Cns_dbfd *dbfd,char *path,char *basename,char *bitmap)
{
        MYSQL_ROW row;
        MYSQL_RES *res;
	char func[21];
        static char check[]="select bitmap from Cns_file_transform_metadata where path='%s' and name='%s'";
        char sql_check[1024];

        strcpy(func,"Cns_get_bitmap");
        sprintf(sql_check,check,path,basename);
        if (Cns_exec_query (func, dbfd, sql_check, &res))
                return (-1);

        if ((row = mysql_fetch_row (res)) == NULL) {
                mysql_free_result (res);
                serrno = ENOENT;
                return (-1);
        }
	strcpy(bitmap,row[0]);
        mysql_free_result (res);
        return (0);		
}
 
int Cns_get_fd_by_actualpath(struct Cns_dbfd *dbfd, char *path, int *fd)
{
        MYSQL_ROW row;
        MYSQL_RES *res;
        char func[21];
        static char check[]="select FD from Cns_seg_transform_metadata where path='%s'";
        char sql_check[1024];

        strcpy(func,"Cns_get_fd_by_actualpath");
        sprintf(sql_check,check,path);
        if (Cns_exec_query (func, dbfd, sql_check, &res))
                return (-1);

        if ((row = mysql_fetch_row (res)) == NULL) {
                mysql_free_result (res);
                serrno = ENOENT;
                return (-1);
        }
        sscanf(row[0],"%d",fd);
        mysql_free_result (res);
        return (0);
}
int Cns_get_path_by_fd(struct Cns_dbfd *dbfd, int fd, char * path,char *name)
{
        MYSQL_ROW row;
        MYSQL_RES *res;
        char func[21]; 
        static char check[]="select path, name from Cns_file_transform_metadata where fileid=%d";
        char sql_check[1024];

        strcpy(func,"Cns_get_path_by_fd");
        sprintf(sql_check, check, fd);
        if (Cns_exec_query (func, dbfd, sql_check, &res))
                return (-1);

        if ((row = mysql_fetch_row (res)) == NULL) {
                mysql_free_result (res);
                serrno = ENOENT;
                return (-1);
        }
        strcpy(path,row[0]);
	strcpy(name,row[1]);
	
        mysql_free_result (res);
        return (0);

}
int Cns_get_fileid_by_fullpath(struct Cns_dbfd *dbfd, char *path, char *filename, int *id)
{
	MYSQL_ROW row;
	MYSQL_RES *res;
	char func[21];
	static char check[]="select fileid from Cns_file_transform_metadata where path='%s' and name='%s'";
	char sql_check[1024];
	strcpy(func,"Cns_get_fileid_by_fullpath");
	sprintf(sql_check, check, path, filename);
	if (Cns_exec_query (func, dbfd, sql_check, &res))
		return (-1);
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return (-1);
	}
	sscanf(row[0],"%d",id);
	mysql_free_result (res);
	return (0);
		
}
int Cns_get_dirlist_by_parent_fileid(struct Cns_dbfd *dbfd, int id, char *dirlist)
{
	MYSQL_ROW row;
	MYSQL_RES *res;
	int i=0;
	char func[21];
	static char check[]="select fileid from Cns_file_transform_metadata where parent_fileid=%d";
	char sql_check[1024];
	strcpy(func,"Cns_get_dirlist_by_parent_fileid");
	sprintf(sql_check, check, id);
	if (Cns_exec_query (func, dbfd, sql_check, &res))
		return -1;
	if ((row = mysql_fetch_row (res)) == NULL) {
		mysql_free_result (res);
		serrno = ENOENT;
		return -1;
	}
	sprintf(dirlist,row[0]);
	while(row = mysql_fetch_row (res)){
		strcat(dirlist, ",");
		strcat(dirlist,row[0]);
	}		
	mysql_free_result (res);
	return (0);	
}
int Cns_get_ftmd_by_fileid(struct Cns_dbfd *dbfd, int id, struct Cns_file_metadata *fmd_entry)
{
        char func[22];
        static char query[] =
                "SELECT \
                 FILEID, PARENT_FILEID, NAME, PATH, FILEMODE, NLINK, DEV, INO, OWNER_UID, GID, \
                 FILESIZE, ATIME, MTIME, CTIME, FILECLASS, STATUS, BITMAP \
                FROM Cns_file_transform_metadata \
                WHERE FILEID = %d";
        MYSQL_RES *res;
        MYSQL_ROW row;
        char sql_stmt[1024];

        strcpy (func, "Cns_get_ftmd_by_fileid");
        sprintf (sql_stmt,  query, id);
        if (Cns_exec_query (func, dbfd, sql_stmt, &res))
                return (-1);
        if ((row = mysql_fetch_row (res)) == NULL) {
                mysql_free_result (res);
                serrno = ENOENT;
                return (-1);
        }
      	Cns_decode_ftmd_entry (row, 0, NULL, fmd_entry);
        mysql_free_result (res);
	return 0;
}
