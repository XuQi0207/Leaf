#include <stdlib.h>
#include <stdio.h>
const  char *volumn[]={"gid","mode","dev","size","path","mtime","uid","ctime","atime","ino","nlink"};
/*match the volumns*/
static int match_volumn(char *vol){
        int i;
        for(i=0;i<11;i++){
		printf("%s\n",volumn[i]);
		printf("%s\n",vol);
                if(strcmp(vol,volumn[i])==0)
                       return i;
        }
        return -1;
}

int main(int argc, char argv[]){
/*	FILE *fp=fopen("ceshi","r");
	if(fp==NULL){
		printf("no\n");
		return -1;
	}
	fseek(fp,0,SEEK_END);
	int len=ftell(fp);
*/
char *b="gid";
	match_volumn(b);
	return 0;
}
