#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "Cns_api.h"

//read key from configure file
int get_conf_value(char *file_path, char *key_name, char *key_value)
{
        FILE *fp = NULL;
        char *line = NULL, *substr = NULL;
	char value[100];
        size_t len = 0, tlen = 0;
        ssize_t read = 0;

    if(file_path == NULL || key_name == NULL || key_value == NULL)
    {
        printf( "config_key parameter is wrong\n");
        return -1;
    }
        fp = fopen(file_path, "r");
        if (fp == NULL)
    {
        printf("open config_file failed\n");
        return -1;
    }
 while ((read = getline(&line, &len, fp)) != -1)
    {
        substr = strstr(line, key_name);
        if(substr == NULL)
        {
            continue;
        }
        else
        {
            tlen = strlen(key_name);
            if(line[tlen] == '=')
            {
                strncpy(value, &line[tlen+1], len-tlen+1);
                tlen = strlen(value);
                *(value+tlen-1) = '\0';
                break;
            }
            else
            {
                printf("config file format is invaild\n");
                fclose(fp);
                return -2;
            }
        }
    }
    if(substr == NULL)
    {
        printf("key: %s is not in config file!\n", key_name);
        fclose(fp);
        return -1;
    }
    strcpy(key_value, value);
    free(line);
    fclose(fp);
    return 0;

}

/*split path and name*/
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
        if (p <= path)  /* path in the form abc or /abc */
                p++;
        *p = '\0';
        return (0);
}

/*remove mount path from the path*/
int pathsplit(char *path, char *mountpath)
{
	if(*path==0 || *path!='/' || *mountpath==0 || *mountpath!='/')
	{
		return -1;
	}
	char *tmp=(char *)malloc(strlen(path)-strlen(mountpath)+1);
	strcpy(tmp, path+strlen(mountpath));
	memset(path, '0', strlen(path));
	strcpy(path,tmp);
	free(tmp);
	return 0;
}

/*print json for test*/
void json_print_array(json_object *obj) 
{
      if(!obj) return;
      int length=json_object_array_length(obj);
      int i;
      for( i=0;i<length;i++) {
              json_object *val=json_object_array_get_idx(obj,i);
              json_print_value(val);
      }
}
void json_print_object(json_object *obj)
{
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

/*mdir multi-level dir*/
int mkdirs(char *muldir, int mode)
{
	int res;
	int i,len;
	char str[512];
	strncpy(str, muldir, 512);
	len=strlen(str);
	for(i=0; i<len; i++){
		if(str[i]=='/' && i!=0){
			str[i]='\0';
			if(access(str, 0)!=0){
				if((res=mkdir(str,mode))!=0)
					return res;
			}
			str[i]='/';
		}
	}
	if(len>0 &&access(str, 0)!=0){
		if((res=mkdir(str, mode))!=0)
			return res;
	}
	return 0;
}


