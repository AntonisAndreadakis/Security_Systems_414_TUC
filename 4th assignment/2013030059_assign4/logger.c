#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#define MD5_LEN 32
#define PATH_LEN 256
#define STR_VALUE(val) #val
#define STR(name) STR_VALUE(name)
#define MAX_PATH 1024


void generateHash(unsigned char *hash, unsigned char *data, size_t len){
	int i;
	for(i=0; i<len; i++){ //the dimension of MD5
		sprintf((char * restrict)&(hash[i*2]),"%02x", data[i]); //fingerprint
		}
}

void log_print(char * var1, char *open, char *deny, const char *path, struct tm* timeinfo, unsigned char *hash){
	// var1 is referred to UID, open represents Access type (write/read etc), deny is for access flag, path is referred
	// to file name, hash is for file fingerprint and struct tm is the standard struct (by default) to use time definition
	char res[MAX_PATH];
	size_t (*original_open)(const char *, int, mode_t);
	original_open = dlsym(RTLD_NEXT, "open");
	/* the log must have append mode and only owner can read and write in it*/
	size_t logf = (*original_open)("./file_logging.log", _IOS_APPEND | S_IREAD | STA_RONLY, S_IRUSR | S_IWUSR);

	sprintf(res,"%s\t%s \t%s \t%s \t%d-%d-%d\t%d:%d:%d \t",var1,open,deny,path,1900+timeinfo->tm_year,timeinfo->tm_mon,timeinfo->tm_mday,timeinfo->tm_hour,timeinfo->tm_min,timeinfo->tm_sec);
	
	size_t (*original_write)(int, const void *, size_t);
	original_write = dlsym(RTLD_NEXT, "write");
	(*original_write)(logf, &res, strlen(res));
	close(logf);
}

void userID(int f, const char *path, char * open, char * action){
	/* create entries for log file */
	int bytes;
	char id[5];
	time_t rawtime;
	struct tm * timeinfo;
	time (&rawtime);
	timeinfo = localtime (&rawtime);
	unsigned char *data;
	unsigned char *hash;
	unsigned char c[MD5_DIGEST_LENGTH];
	MD5_CTX mdContext;

	/*Get system user*/
	uid_t uid = getuid();
	sprintf(id, "%d", uid);

	/* Get hash */
	data = malloc(256);

	if (f != -1){
	/*File is opened.
	* if the right permissions correspond to descriptor, the hash will be produced 
	* else the action_denied become zero and hash is null (because we can't read the file)  */
	MD5_Init(&mdContext);
	bytes = read(f, data, 256);
	if (bytes > 0){
		/*regular file*/
		while(bytes > 0){
		MD5_Update(&mdContext, data, bytes);
		bytes = read(f, data, 256);
		}                
	MD5_Final(c, &mdContext);                
	hash = malloc(MD5_DIGEST_LENGTH * 2);
	generateHash(hash, c, MD5_DIGEST_LENGTH);   
        }
	else if(bytes == 0){
		/* empty file */
		MD5_Update(&mdContext, data, bytes);
		MD5_Final(c, &mdContext);           
		hash = malloc(MD5_DIGEST_LENGTH * 2);
		generateHash(hash, c, MD5_DIGEST_LENGTH);
		}
	else{
		/* can't read the file */
		hash = NULL;
		}
	}
	else{
	/* f == -1, we don't have access to file to produce hash value. */
		hash = NULL;
		action = NULL;
		action = malloc(sizeof(char));
		strcpy(action, "1");
		}
    
    log_print(id, open ,action, path, timeinfo, hash);
    free(data);
}

FILE *fopen(const char *path, const char *mode) {
	printf("Opening %s\n", path);
	int action = 0;
	errno = 0;
	FILE *(*original_fopen)(const char*, const char*);
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	 
	/* add your code here */
	FILE * original_fopen_ret = (*original_fopen)(path, mode);
	if(original_fopen_ret == NULL){
		perror("ERROR opening file!");
		if(errno == EACCES || errno == EPERM){
			fprintf(stdout,"HAVE NO PERMISSION TO OPEN FILE!\n");
			action = 1;
			}
		else if(errno == ENOENT){
			fprintf(stdout,"FILE DOES NOT EXIST!\n");
			return original_fopen_ret;
			}
		else{
			fprintf(stdout,"UNKNOWN ERROR!\n");
			return original_fopen_ret;
			}
	}
	/* ... */
	int i = fileno(original_fopen_ret);
	userID(i,path,"1",(action == 1)? "1":"0");
	return original_fopen_ret;
}

int open(const char *path, int flags,  ...){
	printf("Opening %s\n", path);
	int action = 0;
	int fileDescr;
	va_list ap;
	mode_t mode = -1;
	
	if (!(flags & S_IREAD)){
	size_t (*original_open)(const char *, int);
	original_open = dlsym(RTLD_NEXT, "open");
	fileDescr = (*original_open)(path, flags);
	}
	else{
		va_start(ap, flags);
		mode = va_arg(ap, int);
		va_end(ap);
		va_start (ap, flags);
		mode = va_arg(ap, mode_t);
		va_end(ap);
		size_t (*original_open)(const char *, int, mode_t);
		original_open = dlsym(RTLD_NEXT, "open");
		fileDescr = (*original_open)(path, flags, mode);
		} 
	if (fileDescr == -1){
		if (errno == EACCES || errno == EPERM){
			fprintf(stdout,"HAVE NO PERMISSION TO OPEN FILE!\n");
			action = 1;
		}
		else if (errno == ENOENT){
			fprintf(stdout,"FILE DOES NOT EXIST!\n");
			return fileDescr;
		}
		else{
			fprintf(stdout, "UNKNOWN ERROR!\n");
			return fileDescr;
			}
	}
	userID(fileDescr,path,"1",(action == 1)? "1":"0");
return fileDescr;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	printf("Writing... \n");
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	/* call the original fwrite function */
	size_t original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	/* add your code here */
	int action;
	int max = 0xFFF;
	int fileID;
	char file_name[0xFFF];
	char p[0xFFF];
	ssize_t n;
	if(stream != NULL){
		fileID = fileno(stream);
		sprintf(p,"/proc/self/fd/%d",fileID);
		n = readlink(p,file_name,max);
		if(n<0){
			fprintf(stderr,"Failed to read link!\n");
			exit(1);
			}
	file_name[n] = '\0';
	}
	/* ... */
	char *name = basename(file_name);
	if(original_fwrite_ret < size){
		if (errno == EACCES || errno == EPERM){
			fprintf(stdout,"HAVE NO PERMISSION TO OPEN FILE!\n");
			action = 1;
		}
		else if (errno == ENOENT){
			fprintf(stdout,"FILE DOES NOT EXIST!\n");
			return original_fwrite_ret;
		}
		else{
			fprintf(stdout,"UNKNOWN ERROR!\n");
			return original_fwrite_ret;
			}
	}
	userID(fileID,name,"0",(action == 1)? "1":"0");
	return original_fwrite_ret;
}

ssize_t write(int i, const void *buf, size_t bytes){
	printf("Writing... \n");
	size_t(*original_write)(int, const void*, size_t);
	original_write = dlsym(RTLD_NEXT, "write");
	size_t original_fwrite_ret = (*original_write)(i,buf,bytes);
	int action;
	int max = 0xFFF;
	char file_name[0xFFF];
	char p[0xFFF];
	ssize_t n;
	sprintf(p,"/proc/self/fd/%d",i);
	n = readlink(p,file_name,max);
	if(n<0){
		fprintf(stderr,"Failed to read link!\n");
		exit(1);
		}
	file_name[n] = '\0';
	/* ... */
	char *name = basename(file_name);
	if(original_fwrite_ret == -1){
		if (errno == EACCES || errno == EPERM){
			fprintf(stdout,"HAVE NO PERMISSION TO OPEN FILE!\n");
			action = 1;
		}
		else if (errno == ENOENT){
			fprintf(stdout,"FILE DOES NOT EXIST!\n");
			return original_fwrite_ret;
		}
		else{
			fprintf(stdout,"UNKNOWN ERROR!\n");
			return original_fwrite_ret;
			}
		}
	userID(i,name,"0",(action == 1)? "1":"0");
return original_fwrite_ret;
}

