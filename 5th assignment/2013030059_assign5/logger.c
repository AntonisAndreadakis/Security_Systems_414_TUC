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
#include <limits.h>



#ifndef MAX_SIZE
#define MAX_SIZE 1024
#endif

#ifndef MAX_PATH
#define MAX_PATH 0xFFF
#endif

#ifndef LOFFILE
#define LOGFILE "file_logging.log"
#endif


struct tm *get_time(){
	struct tm *retVal;
	time_t rawtime;
	//get time, adjust on local settings:
	time(&rawtime);
	retVal = localtime(&rawtime);
	//fix issue by adding 1900 to the result:
	retVal->tm_year += 1900;
	retVal->tm_mon++;
return retVal;
}

int file_exists(const char *fileName){
	struct stat b;
return (stat(fileName, &b) == 0);
}

/* An enum to help define a user's action */
enum actionType {CREATE = 0, OPEN = 1, WRITE = 2};

char *get_path(const char *fileName, FILE *fp){

	char *path = malloc(MAX_PATH);
	if(!fp)
		path = realpath(fileName, NULL);	
	else{
		int fd = fileno(fp);
		char proclink[MAX_PATH];
		ssize_t r;
		//concat:
		sprintf(proclink, "/proc/self/fd/%d", fd);
		//read:
		r = readlink(proclink, path, MAX_PATH);
		if(r < 0)
			return NULL;
		//readlink is not null-terminating:
		*(path  + r) = '\0';		
		}
	//Return absolute path or NULL.
	if(!path)
		return NULL;
return path;
}

int fixAccess(const char *mode, int existed){
	enum actionType action;
	//existance of the file doesn't affect actionType:
	if(strcmp(mode, "a") == 0 || strcmp(mode, "a+") == 0){
		//if file not there, user created it:
		action = OPEN;
		if(!existed)
			action = CREATE;
	}
	else if(strcmp(mode, "r") == 0 || strcmp(mode, "r+") == 0)
		action = OPEN;
	else if(strcmp(mode, "w") == 0 || strcmp(mode, "w+") == 0)
		action = CREATE;
	else{
		return -1;
	}
return (int)action;
}

void fixPrivileges(const char *path, mode_t mode){
	//user is root, nothing to do:
	if(getuid() == 0)
		return;
	//unsuccessful:
	if(chmod(path, mode) != 0)
		fprintf(stderr, "File may not exist!\n");
}

unsigned char *generateHash(const char *path, const char *new_data){
	//space for the hash, 16 bytes is default of MD5:
	unsigned char *retVal = (unsigned char *)malloc(MD5_DIGEST_LENGTH);
	MD5_CTX ctx;
	size_t len;
	char *data = (char * )malloc(MAX_SIZE*sizeof(char));
	//open file:
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char *, const char *);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, "rb");
	if(!original_fopen_ret){	
		free(retVal);
		return NULL;		
	}	
	//reading from file:
	MD5_Init(&ctx);
	//read and update context:
	while((len = fread(data, 1, MAX_SIZE, original_fopen_ret)) != 0)
		MD5_Update(&ctx, data, len);
	//if write, new content also hashed:
	if(new_data)
		MD5_Update(&ctx, new_data, strlen(new_data));
	MD5_Final(retVal, &ctx);
	
	fclose(original_fopen_ret);
	free(data);

return retVal;
}

void printHex(FILE *fp, const char *data, size_t n){
	size_t i;
	if(!fp)
		return;
	for(i=0; i<n; i++){
		fprintf(fp,"%02x", data[i]);
		}
	fprintf(fp,"\n");
}
unsigned char *fillZero(size_t n){
	unsigned char *k = (unsigned char *)malloc(n); 
	for(size_t i =0; i < n; i++)
		*(k + i) = 0;
return k;
}
void log_print(char *logfile, uid_t uid, int actionType, int actionFlag, int fileStat, const char *path, struct tm *time, unsigned char *hash){
	// uid is referred to UID, actionType represents Access type (write/read etc), actionFlag is for access flag, path is referred
	// to file name, hash is for file fingerprint and struct tm is the standard struct (by default) to use time definition
	//will make an fopen call definetlly.
	FILE *(*fp_fopen)(const char*, const char*);
	FILE *fp_fopen_ret;

	//if not there, make a log file and fix permissions:
	if(access(logfile, F_OK) == -1){		
		fp_fopen = dlsym(RTLD_NEXT, "fopen");
		fp_fopen_ret = (*fp_fopen)(logfile, "w");
		if(!fp_fopen_ret){
			printf("Error opening log file!");
			exit(-1);
		}
		fixPrivileges(logfile, S_IRWXU | S_IWGRP | S_IWOTH);
        fclose(fp_fopen_ret);  
	}

	fp_fopen = dlsym(RTLD_NEXT, "fopen");
	fp_fopen_ret = (*fp_fopen)(logfile, "a");

	fprintf(fp_fopen_ret,"%u\t%d %d %-1d\t%s\t%d-%d-%d\t%d:%d:%d\t", uid, actionType, actionFlag, fileStat, path, time->tm_year, time->tm_mon, time->tm_mday, time->tm_hour, time->tm_min, time->tm_sec);
	printHex(fp_fopen_ret, (const char *)hash, MD5_DIGEST_LENGTH);

	fclose(fp_fopen_ret);
}

int open(const char *path, int flags, mode_t mode){	
	if(mode < 4095){
		//enable logging:
		FILE *fp = fopen(path, "w");
		if(chmod(path, mode) < 0)
			fprintf(stderr, "open(): Failed!\n");
		fclose(fp);
	}
	int (*original_open_ret)(const char*, int flags, mode_t mode);
	original_open_ret = dlsym(RTLD_NEXT,"open");

return (*original_open_ret)(path, flags, mode);	
}
FILE *fopen(const char *path, const char *mode) {
	printf("\nOpening %s:\n", path);

	int denied;
	int acc_type;
	const char *fPath;
	unsigned char *hash;

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	//check if the file already exists:
	int previousMade = file_exists(path);
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	denied = (!original_fopen_ret) ? 1 : 0;
	//get path, or NULL:
	fPath = (file_exists(path)) ? (get_path(path, NULL)) : (char *)path;
	//decide about the access type:
	acc_type = fixAccess(mode, previousMade);
	//calculate MD5 hash, else zeroes:
	hash = (generateHash(path, NULL)) ? (generateHash(path, NULL)) : (fillZero(MD5_DIGEST_LENGTH));

	log_print(LOGFILE, getuid(), acc_type, denied, file_exists(path), fPath, get_time(), hash);
		
return original_fopen_ret;
}
//above inplementation of fopen, is called by most of encryption libraries
//so if needed to log actions from these libraries, overide with fopen64:
FILE *fopen64(const char *path, const char *mode){
	return fopen(path, mode);
}


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
	printf("\nWriting... \n");

	int denied;
	int acc_type;
	const char *fPath;
	unsigned char *hash;

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	denied = (original_fwrite_ret == nmemb) ? 0 : 1;
	//get path, or NULL:
	fPath = get_path(NULL,stream);
	acc_type = 2;
	//if MD5 hash exists, else fill zeroes:
	hash = (generateHash(fPath, (const char *)ptr)) ? (generateHash(fPath,  (const char *)ptr)) : (fillZero(MD5_DIGEST_LENGTH));

	log_print(LOGFILE, getuid(), acc_type, denied, file_exists(fPath), fPath, get_time(), hash);
return original_fwrite_ret;
}

