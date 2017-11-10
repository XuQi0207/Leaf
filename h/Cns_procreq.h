#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/types.h>
#include <uuid/uuid.h>
#include "client.h"
#if defined(_WIN32)
#define R_OK 4
#define W_OK 2
#define X_OK 1
#define F_OK 0
#define S_ISGID 0002000
#define S_ISVTX 0001000
#include <winsock2.h>
#else
#include <unistd.h>
#include <netinet/in.h>
#endif
#include "marshall.h"
#include "Cgrp.h"
#include "Cns.h"
#include "Cns_server.h"
#include "Cpwd.h"
#include "Cupv_api.h"
#include "rfcntl.h"
#include "serrno.h"
#include "u64subr.h"
#include "Cns_api.h"


void Cns_logreq(char *func,char *logbuf);
int marshall_DIRX (char **sbpp,struct Cns_file_metadata *fmd_entry);
int marshall_DIRXT (char **sbpp,int magic,struct Cns_file_metadata *fmd_entry,struct Cns_seg_metadata *smd_entry);
int Cns_srv_access(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_chclass(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_chdir(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_chmod(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_chown(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_creat(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_delcomment(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_delete(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_deleteclass(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_enterclass(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_getcomment(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_getpath(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_getsegattrs(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_listclass(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip,struct Cns_class_metadata *class_entry,int endlist,DBLISTPTR *dblistptr);
int Cns_srv_listtape(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip,struct Cns_file_metadata *fmd_entry,struct Cns_seg_metadata *smd_entry,int endlist,DBLISTPTR *dblistptr);
int Cns_srv_mkdir(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_modifyclass(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_open(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_opendir(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_queryclass(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_readdir(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip,struct Cns_file_metadata *fmd_entry,struct Cns_seg_metadata *smd_entry,struct Cns_user_metadata *umd_entry,int endlist,DBLISTPTR *dblistptr,DBLISTPTR *smdlistptr);
int Cns_srv_rename(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_updateseg_checksum(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_replaceseg(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_rmdir(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_setatime(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_setcomment(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_setfsize(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_setsegattrs(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_shutdown(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_stat(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_undelete(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_unlink(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_utime(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_setactualpath(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_delactualpath(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_getactualpath(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_setfile_transform_metadata(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_get_Data_daemon (int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_opendir_t(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_readdir_t(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip,struct Cns_file_metadata *fmd_entry,struct Cns_seg_metadata *smd_entry,struct Cns_user_metadata *umd_entry,int endlist,DBLISTPTR *dblistptr,DBLISTPTR *smdlistptr);
int Cns_srv_cat (int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_setseg (int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_download_seg(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip,char *py_module_path);
int Cns_srv_access_t(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_open_t(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_read_t(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_createfile_t (int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_get_virpath(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_touch_t (int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_stat_t (int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_opendir_t_xrd (int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
int Cns_srv_getattr_id(int magic,char *req_data,char *clienthost,struct Cns_srv_thread_info *thip);
