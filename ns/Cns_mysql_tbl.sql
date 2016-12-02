--
--  Copyright (C) 2001-2003 by CERN/IT/DS/HSM
--  All rights reserved
--
--       @(#)Cns_mysql_tbl.sql,v 1.4 2004/03/03 08:51:30 CERN IT-DS/HSM Jean-Philippe Baud
 
--     Create name server MySQL tables.

-- CREATE DATABASE cns_db;
USE cns_db;
CREATE TABLE Cns_class_metadata (
       rowid BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       classid INTEGER,
       name VARCHAR(15) BINARY,
       owner_uid INTEGER,
       gid INTEGER,
       min_filesize INTEGER,
       max_filesize INTEGER,
       flags INTEGER,
       maxdrives INTEGER,
       max_segsize INTEGER,
       migr_time_interval INTEGER,
       mintime_beforemigr INTEGER,
       nbcopies INTEGER,
       nbdirs_using_class INTEGER,
       retenp_on_disk INTEGER)
	ENGINE = InnoDB;

CREATE TABLE Cns_tp_pool (
       rowid BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       classid INTEGER,
       tape_pool VARCHAR(15) BINARY)
	ENGINE = InnoDB;

CREATE TABLE Cns_file_metadata (
       rowid BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       fileid BIGINT UNSIGNED,
       parent_fileid BIGINT UNSIGNED,
       name VARCHAR(231) BINARY,
       filemode INTEGER UNSIGNED,
       nlink INTEGER,
       owner_uid INTEGER UNSIGNED,
       gid INTEGER UNSIGNED,
       filesize BIGINT UNSIGNED,
       atime INTEGER,
       mtime INTEGER,
       ctime INTEGER,
       fileclass SMALLINT,
       status CHAR(1) BINARY)
	ENGINE = InnoDB;

CREATE TABLE Cns_user_metadata (
       rowid BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       u_fileid BIGINT UNSIGNED,
       comments VARCHAR(255) BINARY)
	ENGINE = InnoDB;

CREATE TABLE Cns_seg_metadata (
       rowid BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       s_fileid BIGINT UNSIGNED,
       copyno INTEGER,
       fsec INTEGER,
       segsize BIGINT UNSIGNED,
       compression INTEGER,
       s_status CHAR(1) BINARY,
       vid VARCHAR(6) BINARY,
       side INTEGER,
       fseq INTEGER,
       blockid CHAR(8),
       checksum_name VARCHAR(16),
       checksum INTEGER)
	ENGINE = InnoDB;

CREATE TABLE Cns_unique_id (
       id BIGINT UNSIGNED)
	ENGINE = InnoDB;

CREATE TABLE Cns_file_transform_metadata(
      rowid BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       fileid BIGINT UNSIGNED,
       parent_fileid BIGINT UNSIGNED,
       name VARCHAR(231) BINARY,
       mode INTEGER UNSIGNED,
       dev  INTEGER UNSIGNED,
	path VARCHAR(231) BINARY,
	ino  INTEGER UNSIGNED,
	nlink INTEGER,
       uid INTEGER UNSIGNED,
       gid INTEGER UNSIGNED,
       size BIGINT UNSIGNED,
       atime INTEGER,
       mtime INTEGER,
       ctime INTEGER,
       fileclass SMALLINT,
       status CHAR(1) BINARY)
        ENGINE = InnoDB;

CREATE TABLE Cns_file_transform_metadata (
       rowid BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       fileid BIGINT UNSIGNED,
       parent_fileid BIGINT UNSIGNED,
       name VARCHAR(231) BINARY,
       path VARCHAR(231) BINARY,
       filemode INTEGER UNSIGNED,
       nlink INTEGER,
       dev INTEGER UNSIGNED,
       ino INTEGER UNSIGNED,	
       owner_uid INTEGER UNSIGNED,
       gid INTEGER UNSIGNED,
       filesize BIGINT UNSIGNED,
       atime INTEGER,
       mtime INTEGER,
       ctime INTEGER,
       fileclass SMALLINT,
       status CHAR(1) BINARY,
	bitmap VARCHAR(600) BINARY)
        ENGINE = InnoDB;

CREATE TABLE Cns_unique_transform_id (
       id BIGINT UNSIGNED)
        ENGINE = InnoDB;



ALTER TABLE Cns_class_metadata
       ADD UNIQUE (classid),
       ADD UNIQUE classname (name);
ALTER TABLE Cns_file_metadata
       ADD UNIQUE (fileid),
       ADD UNIQUE file_full_id (parent_fileid, name);
ALTER TABLE Cns_user_metadata
       ADD UNIQUE (u_fileid);
ALTER TABLE Cns_seg_metadata
       ADD UNIQUE (s_fileid, copyno, fsec);
ALTER TABLE Cns_file_transform_metadata
       ADD UNIQUE (fileid),
       ADD UNIQUE file_full_id (parent_fileid, name);

ALTER TABLE Cns_user_metadata
       ADD FOREIGN KEY fk_u_fileid (u_fileid) REFERENCES Cns_file_metadata(fileid);
ALTER TABLE Cns_seg_metadata
       ADD FOREIGN KEY fk_s_fileid (s_fileid) REFERENCES Cns_file_metadata(fileid),
       ADD UNIQUE tapeseg (vid, side, fseq);
ALTER TABLE Cns_tp_pool
       ADD UNIQUE classpool (classid, tape_pool);

