/*
 * Copyright (C) 1999-2000 by CERN/IT/PDP/DM
 * All rights reserved
 */

/*
 * @(#)cns_db.ddl,v 1.11 2000/09/18 09:56:19 CERN IT-PDP/DM Jean-Philippe Baud
 */

typedef unsigned char u_signed64_db[8][1];

			/* name server Raima database */

database cns_db [4096] {
    data file "Cns_file_metadata" contains Cns_file_metadata_db;
    data file "Cns_user_metadata" contains Cns_user_metadata_db;
    data file "Cns_seg_metadata" contains Cns_seg_metadata_db;
    data file "Cns_unique_id" contains Cns_unique_id;
    key file "Cns_file_full_id" contains file_full_id;
    key file "Cns_fmd_fileid" contains fileid;
    key file "Cns_umd_fileid" contains u_fileid;
    key file "Cns_seg_full_id" contains seg_full_id;
    key file "Cns_seg_vid_fseq" contains seg_vid_fseq;
    record Cns_file_metadata_db {
	unique key u_signed64_db	fileid;
	u_signed64_db	parent_fileid;
	char		name[232];
	unsigned int	filemode;
	int		nlink;		/* number of files in a directory */
	unsigned int	uid;
	unsigned int	gid;
	u_signed64_db	filesize;
	int		atime;		/* last access to file */
	int		mtime;		/* last file modification */
	int		ctime;		/* last metadata modification */
	char		status;		/* '-' --> online, 'm' --> migrated */
	compound unique key file_full_id {
	    parent_fileid;
	    name;
	}
    }

    record Cns_user_metadata_db {
	unique key u_signed64_db	u_fileid;
	char		comments[256];	/* user comments */
    }

    record Cns_seg_metadata_db {
	u_signed64_db	s_fileid;
	int		copyno;
	int		fsec;		/* file section number */
	u_signed64_db	segsize;	/* file section size */
	int		compression;	/* compression factor */
	char		s_status;	/* 'd' --> deleted */
	char		vid[7];
	int		fseq;		/* file sequence number */
	unsigned char	blockid[4][1];	/* for positionning with locate command */
	compound unique key seg_full_id {
	    s_fileid;
	    copyno;
	    fsec;
	}
	compound unique key seg_vid_fseq {
	    vid;
	    fseq;
	}
    }

    record Cns_unique_id {
	u_signed64_db	unique_id;
    }
}
