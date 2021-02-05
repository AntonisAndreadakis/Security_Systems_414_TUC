#define _GNU_SOURCE

#include "myLib.h"

void log_entry(const char* path, unsigned const char accessible)
{
	FILE* (*original_fopen)(const char*, const char*);
	FILE* fp;

	char ttime[80], tdate[80], abspath[1024], logbuff[2048];
	struct tm* timeInfo;
	time_t pure_time;
	
	FILE* lp;
	char buffer[1024];
	unsigned char hash[MD5_DIGEST_LENGTH];
	int md5count;
	MD5_CTX md_ctx;

	original_fopen = dlsym(RTLD_NEXT, "fopen");

	//get the full path
	realpath(path, abspath);

	//get time
	time(&pure_time);
	timeInfo = localtime(&pure_time);

	strftime(ttime, 80, "%T", timeInfo);
	strftime(tdate, 80, "%F", timeInfo);

	sprintf(logbuff, "\t");
	sprintf(logbuff, "%d\t%s\t%s\t%s\t%d\t%d\t\t",(unsigned int)getuid(), abspath, tdate, ttime, accessible, action_access);

	lp = original_fopen(abspath, "rb");

	if(lp)
	{
		MD5_Init(&md_ctx);

		while((md5count = fread(buffer, 1, 1024, lp)))
		{
			MD5_Update(&md_ctx, buffer, md5count);
		}

		MD5_Final(hash, &md_ctx);

		for(md5count = 0; md5count < MD5_DIGEST_LENGTH; md5count++)
		{
			sprintf(logbuff + strlen(logbuff), "%02x", hash[md5count]);
		}
	}

	fclose(lp);

	sprintf(logbuff + strlen(logbuff), "\n");

	fp = original_fopen("file_logging.log", "a");

	if(!fp)
	{
		sprintf(logbuff + strlen(logbuff), "file_logging.log could not be open.\n");
		return;
	}

	action_access = 0;
	fputs(logbuff, fp);
	fclose(fp);	
	return;

}

void wlog_entry(FILE* tmp, unsigned const char accessible)
{
	char path[1024], proc[1024];
	ssize_t size;

	sprintf(proc, "/proc/self/fd/%d",fileno(tmp));
	size = readlink(proc, path, 1024);
	path[size] = '\0';

	log_entry(path, accessible);
}

void noLog(const char* path, unsigned const char accessible)
{
	FILE* (*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	char ttime[80], tdate[80], logbuff[2048],abspath[1024];
	struct tm* timeInfo;
	time_t pure_time;
	int i=0;

	FILE* fd = original_fopen("./file_logging.log","a");
	FILE* lp;
	realpath(path, abspath);
	time(&pure_time);
	timeInfo = localtime(&pure_time);

	strftime(ttime, 80, "%T", timeInfo);
	strftime(tdate, 80, "%F", timeInfo);

	sprintf(logbuff, "\t");
	sprintf(logbuff, "%d\t%s\t%s\t%s\t%d\t%d\t\t",(unsigned int)getuid(), abspath, tdate, ttime, accessible, action_access);

	lp = original_fopen(path, "rb");

	// fill hash with zeros 
	if(!lp)
		for (i = 0; i < MD5_DIGEST_LENGTH; i++) 
			sprintf(logbuff + strlen(logbuff), "%02x",0000);

	sprintf(logbuff + strlen(logbuff), "\n");

	if(!fd)
	{
		sprintf(logbuff + strlen(logbuff), "file_logging.log could not be open.\n");
		return;
	}

	fputs(logbuff, fd);
	fclose(fd);
	return;
}

FILE* fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	FILE *my_file = original_fopen(path, mode);

	if(my_file == NULL)
	{
		// printf("errno = %d\n",errno);
		if(errno == EACCES || errno == EPERM)
		{
			// printf("Error.\n");
			action_access = 1;

			if(*mode == 119)
		{
			noLog(path, 0);
		}

		else
			noLog(path, 1);
		}

		else if(errno == ENOENT)
		{
			printf("fopen failed.\n");
			return my_file;
		}
		
		else
			return my_file;
	}

	else
	{
		action_access = 0;

		if(*mode == 119)
		{
			log_entry(path, 0);
		}
		
		else
			log_entry(path, 1);
	}

	original_fopen_ret = (*original_fopen)(path, mode);

	return original_fopen_ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	fflush(stream);

	wlog_entry(stream,2);

	return original_fwrite_ret;
}
