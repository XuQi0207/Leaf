#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include "Cns.h"
#include "Cns_api.h"
#include "serrno.h"

#define MAXPATHLEN 1023 //the largest size of the file path 
#define UNIT_SIZE (1024*1024)
/*errno the mistake recorded by the system*/
static char location[MAXPATHLEN];//the path of the file int the cached server

/*check wether the file exists convet it to data block path, 
 *  *  * path:the path of the target file, actual_path:the path of data block, 
 *   *   * sucess return 0 or return errno*/
int sql_check(const char * path,  char *actual_path,int *filesize)
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

/*read file if it exists, 
 *  * path:the path of the target file   offset:the start of data block  size: size of the data block   buffer: the data stream of the data block, 
 *   * sucess return 0 or return errno*/
int xrdlocal_read(const char *path, size_t size, off_t offset,char *buf)
{
        int fd;
        int res=0;
        int filesize;
        if((res=sql_check(path, location,&filesize))==0){
                Cns_download_seg(path, offset, size, location, filesize);
                fd=open(location, O_RDONLY);
                if(fd==-1){
                        printf("data block open failed\n");
                        return -errno;
                }
                res=pread(fd, buf, size, offset);
                close(fd);
                if(res==-1){
                        printf("data block read failed\n");
                        return -errno;
                }
                return 0;
        }
        return res;
}


int main(int argc, char *argv[])
{
        char buf[1024*1024*5];
        long int size=5*1024*1024-786;
        long int offset=0;
	char *path;
	char *p;
	int res;
	char fullpath[CA_MAXPATHLEN+1];
	int errflg=0;
	if (argc < 2) {
		fprintf (stderr,
		    "usage: %s file\n", argv[0]);
		exit (USERR);
	}
	
	path = argv[1];
	if (*path != '/' && strstr (path, ":/") == NULL) {
		if ((p = getenv ("CASTOR_HOME")) == NULL ||
		    strlen (p) + strlen (path) + 1 > CA_MAXPATHLEN) {
			fprintf (stderr, "%s: invalid path\n", path);
			errflg++;
		} else
			sprintf (fullpath, "%s/%s", p, path);
	} else {
		if (strlen (path) > CA_MAXPATHLEN) {
			fprintf (stderr, "%s: %s\n", path,
			    sstrerror(SENAMETOOLONG));
			errflg++;
		} else
			strcpy (fullpath, path);
	}
	if((res=xrdlocal_read(fullpath,size,offset,buf))==0)
                printf("read success\n%s\n",buf);
        else{
                printf("data block read failed\n");
		printf("%s\n",strerror(res));
                exit(0);
        }
	return 0;
}

