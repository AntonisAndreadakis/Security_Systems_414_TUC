#define _GNU_SOURCE

#if 0 /* Original submission retained below for review. */

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

#endif

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define DEFAULT_LOG_PATH "./file_logging.log"
#define HASH_HEX_LENGTH 32

typedef FILE *(*fopen_fn)(const char *, const char *);
typedef size_t (*fwrite_fn)(const void *, size_t, size_t, FILE *);

static _Thread_local int inside_hook;

static const char *log_path(void)
{
	const char *configured = getenv("ACLOG_PATH");
	return (configured != NULL && configured[0] != '\0') ? configured : DEFAULT_LOG_PATH;
}

static void safe_field(char *destination, size_t size, const char *source)
{
	size_t i;

	if (size == 0)
		return;
	for (i = 0; i + 1 < size && source != NULL && source[i] != '\0'; ++i) {
		char c = source[i];
		destination[i] = (c == '\t' || c == '\n' || c == '\r') ? '?' : c;
	}
	destination[i] = '\0';
}

static int fingerprint_file(const char *path, char output[HASH_HEX_LENGTH + 1])
{
	unsigned char buffer[4096];
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_length = 0;
	EVP_MD_CTX *context;
	ssize_t count;
	int descriptor;
	unsigned int i;

	strcpy(output, "-");
	descriptor = open(path, O_RDONLY | O_CLOEXEC);
	if (descriptor == -1)
		return -1;
	context = EVP_MD_CTX_new();
	if (context == NULL || EVP_DigestInit_ex(context, EVP_md5(), NULL) != 1) {
		EVP_MD_CTX_free(context);
		close(descriptor);
		return -1;
	}
	while ((count = read(descriptor, buffer, sizeof(buffer))) > 0) {
		if (EVP_DigestUpdate(context, buffer, (size_t)count) != 1) {
			EVP_MD_CTX_free(context);
			close(descriptor);
			return -1;
		}
	}
	close(descriptor);
	if (count < 0 || EVP_DigestFinal_ex(context, digest, &digest_length) != 1 ||
	    digest_length != 16) {
		EVP_MD_CTX_free(context);
		return -1;
	}
	EVP_MD_CTX_free(context);
	for (i = 0; i < digest_length; ++i)
		(void)snprintf(output + (i * 2), 3, "%02x", digest[i]);
	return 0;
}

static void append_entry(const char *path, int access_type, int denied)
{
	char clean_path[PATH_MAX];
	char hash[HASH_HEX_LENGTH + 1];
	char date[11];
	char clock_time[9];
	char record[PATH_MAX + 128];
	struct tm local;
	time_t now;
	int descriptor;
	int length;

	safe_field(clean_path, sizeof(clean_path), path != NULL ? path : "(unknown)");
	(void)fingerprint_file(path != NULL ? path : "", hash);
	now = time(NULL);
	if (localtime_r(&now, &local) == NULL)
		return;
	(void)strftime(date, sizeof(date), "%Y-%m-%d", &local);
	(void)strftime(clock_time, sizeof(clock_time), "%H:%M:%S", &local);
	length = snprintf(record, sizeof(record), "%lu\t%s\t%s\t%s\t%d\t%d\t%s\n",
	                  (unsigned long)getuid(), clean_path, date, clock_time,
	                  access_type, denied, hash);
	if (length < 0 || (size_t)length >= sizeof(record))
		return;
	descriptor = open(log_path(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
	                  S_IRUSR | S_IWUSR);
	if (descriptor == -1)
		return;
	(void)fchmod(descriptor, S_IRUSR | S_IWUSR);
	(void)write(descriptor, record, (size_t)length);
	(void)close(descriptor);
}

static int stream_path(FILE *stream, char output[PATH_MAX])
{
	char proc_path[64];
	ssize_t length;
	size_t count;
	int descriptor;

	if (stream == NULL)
		return -1;
	descriptor = fileno(stream);
	if (descriptor == -1)
		return -1;
	if (snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", descriptor) < 0)
		return -1;
	length = readlink(proc_path, output, PATH_MAX - 1);
	if (length < 0)
		return -1;
	/* readlink() cannot return more than the size we asked for (PATH_MAX-1),
	 * but spell that bound out explicitly, on the exact variable used to
	 * index output[], rather than relying on it. */
	count = (size_t)length;
	if (count >= PATH_MAX)
		return -1;
	output[count] = '\0';
	return 0;
}

FILE *fopen(const char *path, const char *mode)
{
	fopen_fn real_fopen;
	void *symbol = dlsym(RTLD_NEXT, "fopen");
	_Static_assert(sizeof(real_fopen) == sizeof(symbol), "POSIX function pointer size");
	memcpy(&real_fopen, &symbol, sizeof(real_fopen));
	FILE *result;
	struct stat status;
	char normalized[PATH_MAX];
	const char *logged_path;
	int existed;
	int saved_errno;

	if (real_fopen == NULL) {
		errno = ENOSYS;
		return NULL;
	}
	if (inside_hook)
		return real_fopen(path, mode);
	inside_hook = 1;
	existed = stat(path, &status) == 0;
	result = real_fopen(path, mode);
	saved_errno = errno;
	logged_path = (result != NULL && realpath(path, normalized) != NULL) ? normalized : path;
	append_entry(logged_path, (!existed && result != NULL) ? 0 : 1,
	             result == NULL && (saved_errno == EACCES || saved_errno == EPERM));
	inside_hook = 0;
	errno = saved_errno;
	return result;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
{
	fwrite_fn real_fwrite;
	void *symbol = dlsym(RTLD_NEXT, "fwrite");
	_Static_assert(sizeof(real_fwrite) == sizeof(symbol), "POSIX function pointer size");
	memcpy(&real_fwrite, &symbol, sizeof(real_fwrite));
	char path[PATH_MAX];
	size_t result;
	int saved_errno;
	int have_path;

	if (real_fwrite == NULL) {
		errno = ENOSYS;
		return 0;
	}
	if (inside_hook)
		return real_fwrite(ptr, size, nmemb, stream);
	inside_hook = 1;
	have_path = stream_path(stream, path) == 0;
	result = real_fwrite(ptr, size, nmemb, stream);
	saved_errno = errno;
	if (result > 0)
		(void)fflush(stream);
	append_entry(have_path ? path : "(unknown)", 2,
	             result < nmemb && (saved_errno == EACCES || saved_errno == EPERM));
	inside_hook = 0;
	errno = saved_errno;
	return result;
}
