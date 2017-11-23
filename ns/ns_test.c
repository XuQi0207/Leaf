#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include "Cns_api.h"

#define BUFLEN 1024*1024

char actual_path[100];

struct timeval start,stop;

int main(int argc, char *argv[])
{
/*
        gettimeofday(&start,0);
	printf("start time: %d   %d\n", start.tv_sec,start.tv_usec);
*/
	/* access*/
/*
      if(xrd_access(argv[1],F_OK)==0)
             printf("data block exists\n");
      else{
              printf("data blcok does not exist\n");
		return 1;
          }
*/
	/* open*/
/*
	if(argc!=3){	
		printf("usage: test for read_open---ns_test filepath 16\n  Example: ns_test /data/xrootdfs/root/leaf/pytoc/upload/night.mkv 16\n");
		exit(0);
	}
	int flag=atoi(argv[2]);
       
       	if(xrd_open(argv[1], flag, 0, actual_path)==0){
              printf("data block open success\n");
	      printf("%s\n",actual_path);
	} else {
              printf("data block open failed\n");
		return 1;
       	}

*/

	/* read*/

//	char *buff=NULL;
	char *buff = (char *)malloc(BUFLEN+1);
	if (argc < 2) {
		printf("usage: test for read---ns_test localpath\n  Example: ns_test /data/xrootdfs/root/leaf/pytoc/upload/test.log\n");
        	exit(0);
	}
	//16 xrootd_read  40 xrootd_write
	int filesize=0;
	int res;
	if((res=xrd_open(argv[1], 16, 0, actual_path, &filesize))==0){
              	printf("data block open success\n");
        } else if(res==EISDIR){
              	printf("It is a directory?\n");
		return 1;
        }else if(res==EINVAL ||res== ENAMETOOLONG){
		printf("PATH is wrong\n");
		return 1;
	}
	else if(res== ENOENT){
		printf("No such file\n");
		return 1;
	}else{
		printf("open data block failed\n");
		return 1;
	}
	int size=1024*1024*1;
	int offset=0;
	int tmp=1;
	int tosize=0;
//	int in = open("/dev/shm/cp.tmp",O_CREAT|O_RDWR,S_IREAD|S_IWRITE);

	while (tosize<size) {
       		if(xrd_read(actual_path,BUFLEN,offset,NULL, argv[1], filesize)==0){
			printf("%d.read success\n",tmp);
		}
	        else{
        		printf("%d.read failed %s\n",tmp, actual_path);
			return 1;
       		}
/*
		if(buff!=NULL){
			lseek(in, offset, SEEK_SET);
			write(in,buff,strlen(buff));
			if(tmp==1||tmp==2){
				gettimeofday(&stop,0);
	        		printf("%d. over time: %d  %d\n",tmp,stop.tv_sec,stop.tv_usec);
			}
		}
*/
		offset=offset+BUFLEN;
                tosize=tosize+BUFLEN;
		tmp++;
	}

/*
		printf("buff length: %d\n",strlen(buff));  
                if(xrd_read(actual_path,721010,0,buff, argv[1], filesize)==0){
                        printf("%d.read success\n",tmp);
                }
                else{
                        printf("%d.read failed %s\n",tmp, actual_path);
                        return 1;
                }
		if(buff!=NULL){
			printf("buff length: %d\n",strlen(buff));
                        write(in,buff,strlen(buff));
		}
*/
//	close(in);
	free(buff);

	
	/* getattr*/
/*
	struct stat buf;
	if(xrd_getattr(argv[1],&buf)==0){
		printf("st_mode%d st_ino%d st_dev%d  st_nlink%d st_uid%d st_gid%d st_size%d st_atime%d st_mtime%d st_ctime%d \n",buf.st_mode,buf.st_ino,buf.st_dev,buf.st_nlink,buf.st_uid,buf.st_gid,buf.st_size,buf.st_atime,buf.st_mtime,buf.st_ctime);
	}else{
		printf("No such file\n");
		return 1;
	}
*/
	/* opendir*/
/*
	int *child_dirid=NULL; //if is NULL return the number of child_dir
	int child_dirnum;
	if((child_dirnum=xrd_opendir(argv[1], child_dirid))>=0){
		printf("childdir is %d\n",child_dirnum);
		if(child_dirid!=NULL){
			for(int i =0;i<child_dirnum;i++){
				printf("%d\n",child_dirid[i]);
			}
		}
		return 0;
	}else if(child_dirnum==-2) {
		printf("no such file\n");
		return 1;
	}else if(child_dirnum==-1){
		printf("not a dir\n");
	}

*/
	/*readdir*/
/*
        int res;
        int i=0;
	std::vector<string> filename;	
	std::vector<struct stat> st;	
        res=xrd_readdir(argv[1],filename, st);
	int nsize=st.size();
	printf("vector element num: %d\n",nsize);
        if(res==0){
                while(i<nsize){
                	printf("NO: %d filename: %s\n",i,filename[i].c_str());
                	printf("st_mode%d st_ino%d st_dev%d  st_nlink%d st_uid%d st_gid%d st_size%d st_atime%d st_mtime%d st_ctime%d \n",st[i].st_mode,st[i].st_ino,st[i].st_dev,st[i].st_nlink,st[i].st_uid,st[i].st_gid,st[i].st_size,st[i].st_atime,st[i].st_mtime,st[i].st_ctime);
                        i++;
                }
        }
        else if(res==-1){
                printf("not dir\n");
        }else if(res ==-2){
                printf("no such file\n");
        }
*/
}

