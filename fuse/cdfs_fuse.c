/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
  Copyright (C) 2011       Sebastian Pipping <sebastian@pipping.org>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall fusexmp.c `pkg-config fuse --cflags --libs` -o fusexmp
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <iostream>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif
#include "Cns_api.h"

static struct fuse_operations xmp_oper;
static char confile[]="/etc/profile1";
static char config_key[]="MOUNT_DIR";
static char config_key2[]="DATA_DIR";
static char mountpath[256];
static char datapath[256];

static int xmp_access(const char *path, int mask)
{
        int res;

        char *tmp=(char *)malloc(strlen(mountpath)+strlen(datapath)+strlen(path)+1);
        sprintf(tmp,"%s%s%s",mountpath,datapath,path);
//	res = access(tmp, mask);
	printf("-----access %s\n", tmp);
	res=xrd_access(tmp, mask);
	free(tmp);
        if (res == -1)
                return -errno;

        return 0;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	
	char *tmp=(char *)malloc(strlen(mountpath)+strlen(datapath)+strlen(path)+1);
	sprintf(tmp,"%s%s%s",mountpath,datapath,path);	
//	res = lstat(tmp, stbuf);
	printf("-------getattr %s\n", tmp);		
	res=xrd_getattr(tmp, stbuf);
	free(tmp);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;
	
	int res;
	int fi_size;
	std::vector<string> filename;
	std::vector<struct stat> st;

        char *tmp=(char *)malloc(strlen(mountpath)+strlen(datapath)+strlen(path)+1);
        sprintf(tmp,"%s%s%s",mountpath,datapath,path);
	res=xrd_readdir(tmp, filename, st);
	fi_size=st.size();
	printf("-----readdir fisie %d\n", fi_size);
	if(res!=0)
		return -errno;
	for(int i=0; i<fi_size; i++){
		if(filler(buf, filename[i].c_str(), &st[i], 0))
			break;
	}
	free(tmp);
	return 0;
/*
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

        char *tmp=(char *)malloc(strlen(mountpath)+strlen(datapath)+strlen(path)+1);
        sprintf(tmp,"%s%s%s",mountpath,datapath,path);

	dp = opendir(tmp);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}
	closedir(dp);
	return 0;
*/
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
        int res;
        int filesize;
        char local_path[256];
        char *tmp=(char *)malloc(strlen(mountpath)+strlen(datapath)+strlen(path)+1);
        sprintf(tmp,"%s%s%s",mountpath,datapath,path);
	printf("--------open  %s\n",tmp);
//	res = open(tmp, fi->flags);
        res=xrd_open(tmp, 16, 0, local_path, &filesize);
        printf("------local: %s\n", local_path);
        free(tmp);
        if(res!=0){
                return -errno;
        }
        return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
        int res;
        int filesize;
        char local_path[256];
        (void) fi;

        char *tmp=(char *)malloc(strlen(mountpath)+strlen(datapath)+strlen(path)+1);
        sprintf(tmp,"%s%s%s",mountpath,datapath,path);
	printf("---------read %s\n", tmp);
        res=xrd_open(tmp, 16, 0, local_path, &filesize);
        if(res!=0)
                return -errno;

        res=xrd_read(local_path, size, offset, buf, tmp, filesize);
        printf("------offset: %d   size: %d   strlen_buf: %d\n", offset,size,strlen(buf));        
        free(tmp);
        if(res==0)
                return size;
        return 0;
/*
        int fd;
        int res;

        (void) fi;
        fd = open(actual_path, O_RDONLY);
        if (fd == -1)
                return -errno;

        res = pread(fd, buf, size, offset);
        if (res == -1)
                res = -errno;

        close(fd);
        return res;
*/
}

static int xmp_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
        int fd;
        int res;

        (void) fi;
        char *tmp=(char *)malloc(strlen(mountpath)+strlen(datapath)+strlen(path)+1);
        sprintf(tmp,"%s%s%s",mountpath,datapath,path);

        fd = open(tmp, O_WRONLY);
        if (fd == -1)
                return -errno;

        res = pwrite(fd, buf, size, offset);
        if (res == -1)
                res = -errno;

        close(fd);
	free(tmp);
        return res;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{

        (void) path;
        (void) fi;
        return 0;
} 

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
        int res;

        char *tmp=(char *)malloc(strlen(mountpath)+strlen(datapath)+strlen(path)+1);
        sprintf(tmp,"%s%s%s",mountpath,datapath,path);
	printf("--------statfs  %s\n", tmp);
        res = statvfs(tmp, stbuf);
	free(tmp);
        if (res == -1)
                return -errno;
        return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
        int res;
        res = readlink(path, buf, size - 1);
        if (res == -1)
                return -errno;

        buf[res] = '\0';
        return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;

	res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = -posix_fallocate(fd, offset, length);

	close(fd);
	return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

int main(int argc, char *argv[])
{
	umask(0);
	int r=get_conf_value(confile, config_key, mountpath);
	int r2=get_conf_value(confile, config_key2, datapath);
	if(r!=0||r2!=0){
		cerr<<"error"<<endl;
	}

	xmp_oper.access = xmp_access;	
	xmp_oper.getattr = xmp_getattr;
        xmp_oper.readdir = xmp_readdir;
        xmp_oper.open = xmp_open;
        xmp_oper.read = xmp_read;
        xmp_oper.write = xmp_write;
	xmp_oper.release = xmp_release;
	xmp_oper.statfs = xmp_statfs;

/*
	xmp_oper.readlink = xmp_readlink;
	xmp_oper.mknod = xmp_mknod;
	xmp_oper.mkdir = xmp_mkdir;
	xmp_oper.symlink = xmp_symlink;
	xmp_oper.unlink = xmp_unlink;
	xmp_oper.rmdir= xmp_rmdir;
	xmp_oper.rename = xmp_rename;
	xmp_oper.link = xmp_link;
	xmp_oper.chmod = xmp_chmod;
	xmp_oper.chown = xmp_chown;
	xmp_oper.truncate = xmp_truncate;
	xmp_oper.fsync = xmp_fsync;
*/
	return fuse_main(argc, argv, &xmp_oper, NULL);
}
