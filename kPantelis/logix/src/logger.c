#define _GNU_SOURCE

#include <limits.h>
#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>





#ifndef LOFFILE
#define LOGFILE "//home/apfel/Desktop/securious-tuc/logix/src/file_logging.log"   // This is hardcoded, in order to monitor you should change as per your needs..
#endif

#ifndef MAXSIZE
#define MAXSIZE 1024
#endif

#ifndef MAXPATH
#define MAXPATH 0xFFF
#endif


/*

	An enum to help define a user's action

*/
enum action_type {CREATE = 0, OPEN = 1, WRITE = 2};

/*
	Utility functions

*/


// this thing is evil..
void escalate_priviledges(const char *path, mode_t mode);

void print_hex(const char *data, size_t len, FILE *fp);
void log_action(char *logfile, uid_t uid, const char *filepath, struct tm *time, int action_type, int action_status, int file_status,unsigned char *hash);

int file_exists(const char *fName);
int resolveAccess(const char *mode, int wasThere);
unsigned char *calculate_hash(const char *path, const char *new_data);
unsigned char *zero_fill(size_t len);
char *get_file_path(const char *fName, FILE *fp);
struct tm *get_time();







/*
	A tricky implementation of fopen, made to log actions.

*/

FILE *fopen(const char *path, const char *mode) 
{


	//stats
	int denied;
	int acc_type;
	const char *fPath;
	unsigned char *hash;
	int exists;


	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	//check if the file already exists.
	int isThere = file_exists(path);

	
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	/*
		Gather up useful insights about the action
	
	*/

	

	//checking whether fopen() denied or not.
	denied = (!original_fopen_ret) ? 1 : 0;

	//getting the abs. file path, or NULL.
	fPath = (file_exists(path)) ? (get_file_path(path, original_fopen_ret)) : (char *)path;

	//decide about the access type.
	acc_type = resolveAccess(mode, isThere);

	//if able calculate an MD5 hash, else pad with zeroes.
	hash = (calculate_hash(path, NULL)) ? (calculate_hash(path, NULL)) : (zero_fill(MD5_DIGEST_LENGTH));

	exists = (acc_type == 0) ? 0 : file_exists(path);
	

	//attempt to log all stats concerning the call.
	log_action(LOGFILE, getuid(), fPath, get_time(), acc_type, denied, exists, hash);
	

	


	/*
	
		Do what the actual function would do.

	*/



	//return the original so the open proc, actually happens.

	return original_fopen_ret;
}

/*

	This implementation of fopen(),gets called from most encryption libraries [openssl as well] because of large file support.
	If wishing to log actions of those libs, we should better override that declaration
	Args:
			What fopen64() would ask..
	Returns:

			What fopen64() would..
	Notes:
			Forces fopen() usage to monitor events..

*/
FILE *fopen64(const char *path, const char *mode)
{

	return fopen(path, mode);


}



/*
	
	Lazy enough to rewrite it, I'll just handle it via fopen()..
	This gets called from "touch " directly or via a call chain from "fd_reopen"->"open".
	In order to monitor creation of files with "touch" cmds we need that thing overwritten.

*/

int open(const char *path, int flags, mode_t mode)
{
	
	//we can work in there
	if(mode < 4095)
	{
		//that trick will enable logging with less code written..
		FILE *fp = fopen(path, "w");

		if(chmod(path, mode) < 0)
			fprintf(stderr, "[open]: Failed to play with permissions\n");

		//no leaks allowed
		fclose(fp);
	}


	//we shall return something..
	int (*original_open_ret)(const char*, int flags, mode_t mode);
	original_open_ret = dlsym(RTLD_NEXT,"open");


	return (*original_open_ret)(path, flags, mode);
	
}





/*
	A tricky implementation of fwrite, made to log actions.

*/


size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	//stats
	int denied;
	int acc_type;
	const char *fPath;
	unsigned char *hash;

	


	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);




	/*
		Gather up useful insights about the action
	
	*/


	//checking whether fwrite() denied or not.
	denied = (original_fwrite_ret == nmemb) ? 0 : 1;

	//getting the abs. file path, or NULL.
	fPath = get_file_path(NULL,stream);

	

	//pretty straightforward when writing.
	acc_type = 2;

	//if able calculate an MD5 hash, else pad with zeroes.
	hash = (calculate_hash(fPath, (const char *)ptr)) ? (calculate_hash(fPath,  (const char *)ptr)) : (zero_fill(MD5_DIGEST_LENGTH));

	

	//attempt to log all stats concerning the call.
	log_action(LOGFILE,getuid(),fPath,get_time(), acc_type, denied, file_exists(fPath), hash);
	





	//return the original so the write proc, actually happens.

	return original_fwrite_ret;
}



/*
		Logs user's actions by writing on file specified by <char *logPath>


*/

void log_action(char *logfile, uid_t uid, const char *filepath, struct tm *time, int action_type, int action_status, int file_status,unsigned char *hash)
{


	//will make an fopen call definetlly.
	FILE *(*fp_fopen)(const char*, const char*);
	FILE *fp_fopen_ret;




	//if not there, make a log file and fix permissions.
	if(access(logfile,F_OK) == -1)
	{
		

		//opening logfile..

		fp_fopen = dlsym(RTLD_NEXT, "fopen");
		fp_fopen_ret = (*fp_fopen)(logfile, "w");



		if(!fp_fopen_ret)
		{
			printf("[log_action] Error opening log file..\n");
			exit(-1);
		}


		//trick for the file to be writable to everyone, i dont know if im root anyways..
		escalate_priviledges(logfile, S_IRWXU | S_IWGRP | S_IWOTH);

		//avoid leaks.
        fclose(fp_fopen_ret);
     
	}

	//if there open it.

	fp_fopen = dlsym(RTLD_NEXT, "fopen");
	fp_fopen_ret = (*fp_fopen)(logfile, "a");

	//write stats.
	fprintf(fp_fopen_ret,"[Log] %u %-60s %d %d-%d-%d %d:%d:%d %d %d ", uid, filepath, file_status,time->tm_year, time->tm_mon, time->tm_mday, time->tm_hour, time->tm_min, time->tm_sec, action_type, action_status);
	print_hex((const char *)hash, MD5_DIGEST_LENGTH, fp_fopen_ret);



	//avoid leaks.
	fclose(fp_fopen_ret);




	

	

}


/*

	Returns system time when called.

	Note:

		 - When in Ubuntu tm_year + 1900 will produce the proper year.
		 - Function handles that field change as well.

*/

struct tm *get_time()
{

	struct tm *retVal;
	time_t rawtime;

	//get time, adjust on local settings.
	time(&rawtime);
	retVal = localtime(&rawtime);

	//fix calibration issue by adding 1900 to the result.
	retVal->tm_year += 1900;
	retVal->tm_mon++;


	return retVal;
}





/*
	
	Returns the full file path, showed by <int fp>.
	Also handles files that cannot open as file_descriptor cause user has insufficient priviledges.

	Args:
			- The filename
			- The file pointer specifying the file.
	Returns:

			- The file path as a char array/string or NULL if failure.
	Note:

			- Upon failure caller must hadle the NULL pointer returned.
			- This will not work on Windows or MacOS [if MacOS is your target handle with fcntl()]
			- This is similar to readlink -e, yet realpath is a NULL TERMINATING instead of afforementioned realpath.
			- This implementation solves the issue of what to do if user has no priviledge to open file, since no file descriptor is used here.
			- Works like charm in any given file.

	


*/

char *get_file_path(const char *fName, FILE *fp)
{

	char *path = malloc(MAXPATH);

	if(!fp)
		path = realpath(fName, NULL);	
	else
	{
		/*
			
			Following technique is buffer ovf. vulnerable

		*/

		//get a descriptor.
		int fd = fileno(fp);

		//init. storing stuctures.
		char proclink[MAXPATH];
		ssize_t r;

		//concat.
		sprintf(proclink, "/proc/self/fd/%d", fd);

		//read.
		r = readlink(proclink, path, 0xFFF);
		
		//handle dummies.
		if(r < 0)
			return NULL;

		//readlink is not null-terminating, handle that as well.
		*(path  + r) = '\0';
	
				

	}



	//Return either absolute path or NULL.
		if(!path)
			return NULL;
		return path;
}


/*
	
	Returns 1 if file exists, 0 if not.
	Args:
			- The filePath as <char *>.
	Notes:
			- Do not use <access()> for checking existance, several issues concerning safety might occur.

	
*/

int file_exists(const char *fName)
{
	struct stat b;
	return (stat(fName, &b) == 0);
}



/*

	Given the mode of syscall and a flag this returns the proper access type.
	Args:
		- <const char *mode> : The mode of syscall (fopen() or other).
		- <int wasThere>: 0 if file just got created, 1 if existed before the call.

	Note:

		- This needs to be called inside fopen() or open() to distinguish OPEN or CREATE actions.
		- The existance of the file itsself has no effect on the attempted user action.

*/

int resolveAccess(const char *mode, int wasThere)
{
	enum action_type action;

	fprintf(stderr, "Open Mode:%s\n", mode);

	//the existance of the file doesn't have any effect on the action_type.
	if(strcmp(mode, "r") == 0 || strcmp(mode, "r+") == 0 || strcmp(mode, "rb") == 0)
		action = OPEN;
	else if(strcmp(mode,"w")==0 || strcmp(mode,"w+")==0 || strcmp(mode, "wb") == 0)
		action = CREATE;
	else if(strcmp(mode,"a")==0 || strcmp(mode,"a+")==0)
	{
		//if the file was not there, user created it.

		action = OPEN;
		if(!wasThere)
			action = CREATE;


	}
	else
	{

		return -1;
	}

	return (int)action;

}




/*

	Opens a file and calculates MD5 hash of its contents.

	Args:
			- <const char *path>: The filepath to open.
			- <const cahr *new_data>: data to be written from fwrite(), NULL if fopen() is caller.
	Returns:
			- The MD5 hash as <unsigned char *>, or NULL if issue upon file pointer occurs.

	Notes:

			-Docs: https://www.openssl.org/docs/man1.1.0/man3/MD5_Final.html
			-Caller should handle the NULL return event.
			-If access on file is denied no hash is returned.
			-If caller writes in a file with content, new content is also hashed.

	If uncomment:

			-Priviledge escalation will change the behavior of the function to following.
			-In case user is not root, this executes an escallation of priviledges in order to get access to locked files with content and generate the hash.



*/


unsigned char *calculate_hash(const char *path, const char *new_data)
{

	//allocate some space for the hash, should be like 16 bytes.
	unsigned char *retVal = (unsigned char *)malloc(MD5_DIGEST_LENGTH);

	MD5_CTX ctx;
	size_t len;
	char *data = (char * )malloc(MAXSIZE*sizeof(char));

	/* Unused for now

	//escalating priviledges.
	struct stat old_priv;
	stat(path, &old_priv);
	escalate_priviledges(path, S_IRWXU | S_IWGRP | S_IWOTH);

	*/

	//opening the file.

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char *, const char *);

	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, "rb");


	//erro handling is better than seg_fault.
	if(!original_fopen_ret)
	{
		//fprintf(stderr, "[Hash] Unable to open file..\n");
		free(retVal);
		return NULL;
		
	}


	
	//reading from file, hashing as well.

	//Init. context.
	MD5_Init(&ctx);

	//read and update context, byte-wise.
	while((len = fread(data, 1, MAXSIZE, original_fopen_ret)) != 0)
		MD5_Update(&ctx, data, len);

	//if write action , new content must also be hashed.
	if(new_data)
		MD5_Update(&ctx, new_data, strlen(new_data));

	


	/* Unused for now

	//have to erase my cheats, else they'll know my actions.
	escalate_priviledges(path, old_priv.st_mode);

	
	*/

	//finalize hash.
	MD5_Final(retVal, &ctx);


	//avoid leaks
	fclose(original_fopen_ret);
	free(data);


		



	return retVal;

}

/*

	Returns a block of <size_t> len, as zero padded.

	Args:
			- <size_t len> The length of the block to be padded.
	Returns: 
			- The block filled with zeros.

	Notes:
			- This handles space allocation as well.

*/

unsigned char *zero_fill(size_t len)
{

	unsigned char *retVal = (unsigned char *)malloc(len); 
	for(size_t i =0; i < len; i++)
		*(retVal + i) = 0;



	return retVal;

}

/*
	
	Changes the read priviledge for a specific file.


	Notes:
			- This is a great cheat, if used right.
			- Can bu used to obtain file content in order to generate hash.
			- Alternative: "sudo ./logger" or "sudo make run", the last will escalate "test_aclog" as well.
			- Remember: If you escalate your priviledges at some point, you should de-escalate in another else the admin will knnow.
*/

void escalate_priviledges(const char *path, mode_t mode)
{

	

	//user is root, nothing to do.
	if(getuid() == 0)
		return;

	//failed to cheat.
	if(chmod(path, mode) != 0)
		fprintf(stderr, "File does not exist, or admin is higly skilled ..\n");
	
	


}

/*

	Prints a stream of data in the desired FILE as hex.
	Args:
			- <const char *data>: A stream of data.
			- <size_t len>: Length of data to be printed.
			- <FILE *fp>: A file pointer to where the data will be printed.
	Notes:

			- Can be used for printing data in stdout,stderr.
			- Can be also used for writing in open files.


*/

void print_hex(const char *data, size_t len, FILE *fp)
{

	//assume dummies.
	if(!fp)
		return;

	//parse and print.
	for (size_t i = 0; i < len; i++)
		fprintf(fp,"%02x",data[i]);

	fprintf(fp, "\n");
}


