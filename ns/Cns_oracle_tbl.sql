--
--  Copyright (C) 1999-2003 by CERN/IT/PDP/DM
--  All rights reserved
--
--       @(#)Cns_oracle_tbl.sql,v 1.18 2004/03/03 08:51:31 CERN IT-PDP/DM Jean-Philippe Baud
 
--     Create name server Oracle tables.

CREATE TABLE Cns_class_metadata (
       classid NUMBER(5),
       name VARCHAR2(15),
       owner_uid NUMBER(6),
       gid NUMBER(6),
       min_filesize NUMBER,
       max_filesize NUMBER,
       flags NUMBER(2),
       maxdrives NUMBER(3),
       max_segsize NUMBER,
       migr_time_interval NUMBER,
       mintime_beforemigr NUMBER,
       nbcopies NUMBER(1),
       nbdirs_using_class NUMBER,
       retenp_on_disk NUMBER);

CREATE TABLE Cns_tp_pool (
       classid NUMBER(5),
       tape_pool VARCHAR2(15));

CREATE TABLE Cns_file_metadata (
       fileid NUMBER,
       parent_fileid NUMBER,
       name VARCHAR2(231),
       filemode NUMBER(6),
       nlink NUMBER(6),
       owner_uid NUMBER(6),
       gid NUMBER(6),
       filesize NUMBER,
       atime NUMBER(10),
       mtime NUMBER(10),
       ctime NUMBER(10),
       fileclass NUMBER(5),
       status CHAR(1))
	STORAGE (INITIAL 5M NEXT 5M PCTINCREASE 0);

CREATE TABLE Cns_user_metadata (
       u_fileid NUMBER,
       comments VARCHAR2(255));

CREATE TABLE Cns_seg_metadata (
       s_fileid NUMBER,
       copyno NUMBER(1),
       fsec NUMBER(3),
       segsize NUMBER,
       compression NUMBER,
       s_status CHAR(1),
       vid VARCHAR2(6),
       side NUMBER (1),
       fseq NUMBER(10),
       blockid RAW(4),
       checksum_name VARCHAR2(16),
       checksum NUMBER);

CREATE SEQUENCE Cns_unique_id START WITH 3 INCREMENT BY 1;

ALTER TABLE Cns_class_metadata
       ADD CONSTRAINT pk_classid PRIMARY KEY (classid)
       ADD CONSTRAINT classname UNIQUE (name);
ALTER TABLE Cns_file_metadata
       ADD CONSTRAINT pk_fileid PRIMARY KEY (fileid)
       ADD CONSTRAINT file_full_id UNIQUE (parent_fileid, name)
	USING INDEX STORAGE (INITIAL 2M NEXT 2M PCTINCREASE 0);
ALTER TABLE Cns_user_metadata
       ADD CONSTRAINT pk_u_fileid PRIMARY KEY (u_fileid);
ALTER TABLE Cns_seg_metadata
       ADD CONSTRAINT pk_s_fileid PRIMARY KEY (s_fileid, copyno, fsec);

ALTER TABLE Cns_user_metadata
       ADD CONSTRAINT fk_u_fileid FOREIGN KEY (u_fileid) REFERENCES Cns_file_metadata(fileid);
ALTER TABLE Cns_seg_metadata
       ADD CONSTRAINT fk_s_fileid FOREIGN KEY (s_fileid) REFERENCES Cns_file_metadata(fileid)
       ADD CONSTRAINT tapeseg UNIQUE (vid, side, fseq);
ALTER TABLE Cns_tp_pool
       ADD CONSTRAINT classpool UNIQUE (classid, tape_pool);
