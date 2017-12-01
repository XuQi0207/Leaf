#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include "Cns_api.h"


#define MAXPATHLEN 1023 //the largest size of the file path 
#define UNIT_SIZE (1024*1024)
#define THREAD_NUM 5

struct thread_argument
{
	char remote_path[100];
	int offset;
	int size;
	char local_path[100];
	int filesize;
};
void *thread_download(void *);

/*errno the mistake recorded by the system*/
static char location[MAXPATHLEN];//the path of the file int the cached server

int path_filter(char *path){
	char c[]="/data/xrootdfs";
	char *p;
	char *tmp_path=(char *)malloc(strlen(path)-strlen(c)+1);
	if((p=strstr(path, c))==NULL){
		printf("No such subpath of the path\n");
		return 1;
	}else if(p==path){
		strncpy(tmp_path, path+strlen(c), (strlen(path)-strlen(c)));
		tmp_path[strlen(path)-strlen(c)]='\0';
		strcpy(path,tmp_path);
	}else{
		printf("the subpath is not corect\n");
		return 1;
	}
	free(tmp_path);
	return 0;
}
/*check wether the file exists convet it to data block path, 
 *  *  * path:the path of the target file, actual_path:the path of data block, 
 *   *   * sucess return 0 or return errno*/
int sql_check(char * path,  char *actual_path, int *filesize)
{
        int fd;
        int mode;
        if(*path!='/'){
                return  EINVAL;
        }
        if(strlen(path)>MAXPATHLEN){
                return  ENAMETOOLONG;
        }
        if(Cns_cat_segmetadata(path, actual_path, &fd, filesize, &mode)){//get the fileid and the path of the data file
                return ENOENT;
        }
        if(S_ISDIR(mode)){
                return EISDIR;
        }
        if(strcmp(actual_path,"FDNDY")==0){
                Cns_file_create(path,actual_path,*filesize);//fallocate the data file
                int block_num=(*filesize)/UNIT_SIZE;
                if(((*filesize)%UNIT_SIZE)!=0)
                        block_num+=1;
                Cns_set_segmetadata_by_fd(path,fd,*filesize,actual_path,block_num);//update the segmetadata
        }
        return 0;
}
/*file wether exists, path:the path of the target file,  it exists return 0 or return errno*/
int xrd_access(const char *path,int mask)
{
        int res=0;
        int filesize;
	char *path_t=(char *)malloc(strlen(path)+1);
	strcpy(path_t,path);
	if(path_filter(path_t))
		return 1;
        if((res=sql_check(path_t,location,&filesize))==0){
        /*      res=access(location, F_OK); */
                res=Cns_access_t(location,mask);
        }
	free(path_t);
        return res;
}
/*open file if it exists, 
 *  * path:the path of the target file  flags:open mode  mode:access permission bits(only use when create file), 
 *   * success return 0 or return errno */
int xrd_open(const char *path, int flags, mode_t mode, char * actual_path, int *filesize)
{
        int res=0;
	char *path_t=(char *)malloc(strlen(path)+1);
        strcpy(path_t,path);
	if(path_filter(path_t))
		return 1;
	if(flags==16){//read only mode
        	if((res=sql_check(path_t,location,filesize))==0){
/*
        		if(mode!=0)
        			res=open(location, flags, mode);
      	  		else
        			res=open(location, flags);
*/
			strcpy(actual_path, location);
//                	res=Cns_open_t(location, flags);
        	}
	}else if(flags==40){//write only  mode
		res=Cns_touch_t(path_t,location);
		strcpy(actual_path,location);
	}else if(flags==32){//read and write mode
		res=EPERM;
	}else{
		res=EINVAL;
	}
        free(path_t);
        return res;
}

/*read file if it exists, 
 *  * actual_path:the localpath of the target file   offset:the start of data block  size: size of the data block
 *   * sucess return 0 or return errno*/
int xrd_read(const char *actual_path, size_t size, off_t offset,char *buff, char *path, int filesize)
{

	int i;
        int res=0;
	char *path_t=(char *)malloc(strlen(path)+1);
	strcpy(path_t, path);
	if(path_filter(path_t))
		return 1;
/*
	pthread_t thread[THREAD_NUM];
	void *thread_return[THREAD_NUM];
	struct thread_argument arg;
	int wait_thread_end;
*/
//	Cns_get_virpath(actual_path_t, path_t);/*物理路径查询远程路径*/
//        if((res=sql_check(path_t, location, &filesize))==0){/*在open中一次解决*/

		res=Cns_download_seg(path_t, offset, size, location, filesize, buff);
//		if(buff!=NULL){
//			res=Cns_read_t(location, buff, size, offset, path_t);
//		}
/*		
		strcpy(arg.remote_path, path_t);
		int sblock_num=offset/UNIT_SIZE;
		arg.offset=sblock_num*UNIT_SIZE;
		arg.size=UNIT_SIZE;
		strcpy(arg.local_path, location);
		arg.filesize=filesize;
		for(i=0; i<THREAD_NUM; i++){
			arg.offset=arg.offset+UNIT_SIZE*i;
			if(pthread_create(&thread[i], NULL, thread_download, (void*)&arg)){
				perror("Pthread create fail\n");
				exit(1);
			}
		}
		for(i=0; i<THREAD_NUM; i++){
			if(wait_thread_end=pthread_join(thread[i],&thread_return[i])){
				perror("Pthread join fail\n");
				exit(1);
			}
		}
		res=Cns_read_t(location, buff, size, offset, path_t);
*/
        free(path_t);
        return res;
}
/*
void *thread_download(void *arg)
{
	struct thread_argument *arg_thread;
	arg_thread=(struct thread_argument *)arg;
	Cns_download_seg(arg_thread->remote_path, arg_thread->offset, arg_thread->size, arg_thread->local_path, arg_thread->filesize);
	return (void *)0;	
}
*/
int xrd_getattr(const char *path, struct stat *buf)
{
        int res=0;
        int filesize;
        char *path_t=(char *)malloc(strlen(path)+1);
        strcpy(path_t,path);
        if(path_filter(path_t))
		return 1;
	res=sql_check(path_t,location,&filesize);
        if(res==0||res==21){
                res=Cns_stat_t(path_t,buf);
        }
        free(path_t);
        return res;	
}

int xrd_opendir(const char *path, int *child_dirid)
{
	int res;
	int res1;
	int filesize;
	int child_dirnum=0;
	int size=1000;
	int *child_dirlist=(int *)malloc(size*sizeof(int));
	char *path_t=(char *)malloc(strlen(path)+1);
	memset(child_dirlist, -1, 1000);
	strcpy(path_t,path);
	if(path_filter(path_t))
		return 1;
	if(((res=sql_check(path_t,location,&filesize)))==EISDIR){
		res1=Cns_opendir_t_xrd(path_t, child_dirlist);	
	}
	
        if(res==0)
                child_dirnum= -1; //is a file
	else if(res==EISDIR && res1==0){
		while(child_dirlist[child_dirnum]!=-1 && child_dirnum<size){
			if(child_dirid!=NULL){
				child_dirid[child_dirnum]=child_dirlist[child_dirnum];
			}
			child_dirnum++;
		}	
	}
	else
		child_dirnum=-2; //not exist
	free(path_t);
	free(child_dirlist);
	return child_dirnum;
}

int xrd_readdir(const char *path, vector <string> &filename, vector <struct stat> &child_stat)
{
        int i;
        int child_dirnum;
        int child_dirlist[1000];
        int res=0;
        child_dirnum=xrd_opendir(path, child_dirlist);
        struct Cns_file_transform_stat child_dir;
	struct stat st_tmp;
	string filename_tmp;
        if(child_dirnum>=0){
                for(i=0;i<child_dirnum;i++){
                        xrd_getattr_fid(child_dirlist[i], &child_dir);
                        filename_tmp=string(child_dir.filena);
			filename.push_back(filename_tmp);
                        st_tmp.st_mode=child_dir.mode;
                        st_tmp.st_ino=child_dir.ino;
                        st_tmp.st_dev=child_dir.dev;
                        st_tmp.st_nlink=child_dir.nlink;
                        st_tmp.st_uid=child_dir.uid;
                        st_tmp.st_gid=child_dir.gid;
                        st_tmp.st_size=child_dir.size;
                        st_tmp.st_atime=child_dir.atime;
                        st_tmp.st_mtime=child_dir.mtime;
                        st_tmp.st_ctime=child_dir.ctime;
			child_stat.push_back(st_tmp);
                }
        }else if(child_dirnum==-1){
                res=-1;
        }else if(child_dirnum==-2){
                res=-2;
        }
        return res;
}

int xrd_getattr_fid(int fileid, struct Cns_file_transform_stat * buf)
{
	int res;
	res=Cns_getattr_id(fileid, buf);
	return res;
}

int xrd_write(const char *actual_path, size_t size, off_t offset)
{
	 
}
int xrd_close(const char *actual_path)
{
	
}
