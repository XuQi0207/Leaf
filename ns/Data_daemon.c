//
//  Data_daemon.c
//  Nsdaemon
//
//  Created by MIlo on 2016/10/11.
//  Copyright © 2016年 MIlo. All rights reserved.
//
// Daemon -- fill the database by Nsdaemon

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <json/json.h>
#include <sys/stat.h>
#include "Cns.h"
#include "Cns_api.h"
#include "serrno.h"
#include "Cgetopt.h"
#define DIRMAXSIZE 100
#define ELEMENTTYPE char

/*Variable declaration*/
static char url[]="http://202.122.37.90:28001/list?";
static char autiontic[]="uid=0&gid=0&path=";
static char **filename;
static int file_num=0;//record the order of files which are stored
static int num_temp=0;//record the order of structs which are stored
char temp[11][64]={0};
char vol_name[11][64]={0};
struct Cns_filestat *st;
const char *volumn[]={"ino","mtime","ctime","atime","nlink","uid","dev","gid","path","size","mode"};

typedef struct Node{
	char data[DIRMAXSIZE];
	struct Node *next;
}Qnode;
typedef struct {
	Qnode *front;
	Qnode *rear;
	int size;
}Queue;
Queue *q;
Queue *dir_Init(){
	Queue *q=(Queue *)malloc(sizeof(Queue));
	q->front=NULL;
	q->rear=NULL;
	q->size=0;
	return q;	
}
int dir_Isempty(Queue *q){
	if(q->size==0)
		return 1;
	return 0;
}
void dir_Push(Queue *q, char *item){
	Qnode *qnode=(Qnode *)malloc(sizeof(Qnode));
	strcpy(qnode->data, item);
	qnode->next=NULL;
	if(q->front==NULL){
		q->front=qnode;
	}
	if(q->rear==NULL){
		q->rear=qnode;
	}
	else{
		q->rear->next=qnode;
		q->rear=qnode;	
	}
	q->size++;
}
void dir_Pop(Queue *q,char *item){
	if(dir_Isempty(q)){
		printf("queue empty\n");
		return;
	}
	Qnode *temp=q->front;
	if(q->front==q->rear){
		q->front=NULL;
		q->rear=NULL;
	}
	else{
		q->front=q->front->next;
	}
	strcpy(item, temp->data);
	q->size--;
	free(temp);
}
void dir_Print(Queue *q){
	if(dir_Isempty(q)){
           	printf("queue empty\n");
                return;
        }
	Qnode *qnode=q->front;
	while(qnode!=NULL){
		printf("%s\n", qnode->data);
		qnode=qnode->next;
	}

}

/*print json for test*/
void json_print_value(json_object *obj);
static void json_print_array(json_object *obj) {
      if(!obj) return;
      int length=json_object_array_length(obj);
      int i;
      for( i=0;i<length;i++) {
              json_object *val=json_object_array_get_idx(obj,i);
              json_print_value(val);
      }
}
static void json_print_object(json_object *obj) {
      if(!obj){
          printf("over\n");
          return;
          }
      json_object_object_foreach(obj,key,val) {
          printf("%s => ",key);
          json_print_value(val);
      }
 }
void json_print_value(json_object *obj)
{
        if(!obj)
                return ;
        json_type type=json_object_get_type(obj);
        if(type==json_type_boolean){
                if(json_object_get_boolean(obj)) {
                 printf("true\n");
                 } else {
                        printf("false\n");
                }
        }
        else if(type == json_type_double) {
          printf("double    %lf",json_object_get_double(obj));
      } else if(type == json_type_int) {
          printf("int     %d",json_object_get_int(obj));
      } else if(type == json_type_string) {
          printf("string: %s",json_object_get_string(obj));
     } else if(type == json_type_object) {
          printf("object\n");
          json_print_object(obj);
      } else if(type == json_type_array) {
          json_print_array(obj);
          printf("array\n");
      } else {
          printf("ERROR\n");
      }
      printf("\n");
  }

/*match the volumns*/
static int match_volumn(char *vol){
	int i;
	for(i=0;i<11;i++){
		if(strcmp(vol,volumn[i])==0){
			//printf("vol_location:%d  vol_val:%s\n",i,volumn[i]);
			return i;
		}
	}
	return -1;
}
/*print the stat_struct*/
static void printf_stat(int t, struct Cns_filestat st){
	printf("num:%d  name:%s  ino:%d  mtime:%d  ctime:%d  atime:%d  nlink:%d  uid:%d  dev:%d  gid:%d  path:%s  size:%d  mode:%d\n",t,st.name,st.ino,st.mtime,st.ctime,st.atime,st.nlink,st.uid,st.dev,st.gid,st.path,st.filesize,st.filemode);
}
/*Get the number of files*/
static void get_filenumber(json_object *obj){
	if(!obj) 
        	return ;
    	json_object_object_foreach(obj,key,val){
        	json_type type=json_object_get_type(obj);
        	if(type==json_type_object){
                	file_num++;
       		 }else{
                	printf("Json_object is wrong\n");
                	return ;
        	}    
   	}   
}
/*Deal with the json and divide it into struct stat*/
static void json_setstat(json_object *obj){
    int i=0;
    if(!obj) 
        return ;
    json_object_object_foreach(obj,key,val){
    	json_type type=json_object_get_type(obj);
	if(type==json_type_object){
		strcpy(vol_name[i], key);
		strcpy(temp[i],json_object_get_string(val));
		i++;
	}else{
		printf("Json_object is wrong\n");
		return ;
	}	
    }
    int j;
    for(j=0;j<11;j++){
	int location=match_volumn(vol_name[j]);
	if(location==-1)
		printf("NO such a volumn%d\n",j);
	else{
		switch(location){
                        case 0:st[num_temp].ino=atoi(temp[j]);break;
			case 1:st[num_temp].mtime=atoi(temp[j]);break;
			case 2:st[num_temp].ctime=atoi(temp[j]);break;
                        case 3:st[num_temp].atime=atoi(temp[j]);break;
                        case 4:st[num_temp].nlink=atoi(temp[j]);break;
                        case 5:st[num_temp].uid=atoi(temp[j]);break;
                        case 6:st[num_temp].dev=atoi(temp[j]);break;
                        case 7:st[num_temp].gid=atoi(temp[j]);break;
                        case 8:strcpy(st[num_temp].path,temp[j]);break;
                        case 9:st[num_temp].filesize=atoi(temp[j]);break;
                        case 10:st[num_temp].filemode=atoi(temp[j]);break;
		}
	}
    }
    strcpy(st[num_temp].name,filename[num_temp]);
//     printf_stat(num_temp,st[num_temp]);
    num_temp++;
}
static void json_object_getkey(json_object *obj){
    int i=0;
    int j=0;
    filename=(char **)malloc(file_num*(sizeof(char *)));
    st=(struct Cns_filestat *)malloc(file_num*sizeof(struct Cns_filestat));
    for(j=0;j<file_num;j++){
	filename[j]=(char *)malloc(64*sizeof(char));
    }
    if(!obj){
        printf("No json_object!\n");
        return;
    }
    json_object_object_foreach(obj,key,val){
        if(!obj)
            return;
        json_type type=json_object_get_type(obj);
        if(type==json_type_object){
            strcpy(filename[i], key);
            json_setstat(val);
            i++;
        }else{
            printf("json_object is wrong /n");
        }
    }
	
}
/*read the cache file and get the columns*/
static int process_json(void){
    FILE *fp=fopen("data.json","r");
    if(fp==NULL){
        printf("no such file \n");
        return -1;
    }
    /*!!Read from memory!!*/
    fseek(fp,0,SEEK_END);
    int len=ftell(fp);
    printf("file size is %d\n",len);
    fseek(fp,0,SEEK_SET);
    char *buf=(char *)malloc(len*sizeof(char)+1);
    fgets(buf,len+1,fp); 
//    printf("readbufis:%s\n",buf);
//    printf("read bufsize:%lu\n",strlen(buf));
    json_object *obj=json_tokener_parse(buf);
    if(is_error(obj))
        printf("is_error!\n");
//  json_print_value(obj);
    get_filenumber(obj);
    json_object_getkey(obj);
    json_object_put(obj);
    num_temp=0;
    fclose(fp);
    free(buf);
    remove("data.json");
    return 0;
}
/*write to the cachefile*/
static size_t process_data(char *buffer, size_t size, size_t nmemb, void *user_p)
{
    FILE *fp = (FILE *)user_p;
    size_t return_size = fwrite(buffer, size, nmemb, fp);
   // printf("%s\n", buffer);
    return return_size;
}
/*Get metadata_json by curl*/
static int leaf_getcurl(char *path){
    CURL *curl;
    CURLcode ret;
    char *url_path=(char *)malloc(strlen(url)+strlen(path)+strlen(autiontic)+1);
    strcpy(url_path,url);
    strcat(url_path,autiontic);
    strcat(url_path,path);
    printf("%s\n",url_path);
    /*!!write into memory!!*/
    FILE *fp=fopen("data.json","ab+");
    curl_global_init(CURL_GLOBAL_ALL);
    curl=curl_easy_init();
    if(curl){
        curl_easy_setopt(curl, CURLOPT_URL, url_path);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &process_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        ret=curl_easy_perform(curl);
        if(ret!=CURLE_OK ){
            fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(ret));
	    remove("data.json");
	    exit(0);
	}
        curl_global_cleanup();
    }
    fclose(fp);
    free(url_path);
    return 0;
}
/*	Cns_splitname - split a pathname into dirname and basename */
/*
 *  *	"/"	-->	path = "/", basename = "/"
 *   *	"/abc	-->	path = "/", basename = "abc"
 *    *	"/abc/def -->	path = "/abc", basename = "def"
 *     *	"abc"	-->	path = "", basename = "abc"
 *      */

int splitname(char *path, char *basename)
{
	char *p;

	if (*path == 0)  {
		return (-1);
	}

	if (*path != '/') {
		return (-1);
	}

	/* silently remove trailing slashes */

	p = path + strlen (path) - 1;
	while (*p == '/' && p != path)
		*p = '\0';

	if ((p = strrchr (path, '/')) == NULL)
		p = path - 1;
	strcpy (basename, (*(p + 1)) ? p + 1 : "/");
	if (p <= path)	/* path in the form abc or /abc */
		p++;
	*p = '\0';
	return (0);
}

/*Write the columns into DB & get subdir_path*/
static int set_metadata(char *basename){
	int i;
	int cursubdir_num=0;
	strcpy(filename[0], basename);
	strcpy(st[0].name, basename);
	for(i=0;i<file_num;i++){
//		printf("filename    %s   ",filename[i]);
//		printf_stat(i,st[i]); 
		 if(Cns_setfile_transform_metadata(filename[i],st[i])){
			printf("usage: insert failed\n");	
		}
		if(st[i].filemode & S_IFDIR && i>0){
			dir_Push(q, st[i].path);
		}
	}
}

int set_transform_filemetadata(){
    int i;
    char basename[21];
    char path[100]; 
    while(!dir_Isempty(q)){
	    dir_Pop(q,path);
//	printf("%s\n",path);
	    leaf_getcurl(path);
	    splitname(path, basename);
	    process_json();
	    set_metadata(basename);
	    for(i=0;i<file_num;i++){
     		   free(filename[i]);
   	    }
   	    file_num=0;
   	    free(filename);
            free(st);
    }
    return 0;

}

int main(int argc, char *argv[]){
    if(argc<2){
	printf("usage:%s file location\n",argv[0]);
	exit(0);
    }
    if(argv[1][0]!='/'){
	printf("usage: %s wrong loacation\n",argv[1]);
    }    
//    char path[21]="/root/leaf";
    q=dir_Init();
    dir_Push(q,argv[1]); 
    set_transform_filemetadata();
    return 0;
}

