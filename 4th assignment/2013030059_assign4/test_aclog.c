#include <stdio.h>
#if 0 /* Original submission retained below for review. */
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

/*
static int uid_t euid, ruid;

void do_setuid(void){
	int status;
	#ifdef _POSIX_SAVED_IDS
		status = seteuid (euid);	
	#else
		status = setreuid (reuid, euid);
	#endif
		if(status < 0){
			fprintf(stderr, "COULD NOT SET UID!\n");
			exit(status);
			}
	}

void undo_setuid(void){
	int status;
	#ifdef _POSIX_SAVED_IDS
		status = seteuid (ruid);	
	#else
		status = setreuid (euid, ruid);
	#endif
		if(status < 0){
			fprintf(stderr, "COULD NOT SET UID!\n");
			exit(status);
			}
	}
*/

int main(void) {
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	
	//ruid = getuid();
	//euid = geteuid();
	//undo_setuid();
	
	/* add your code here */
	/* test1: fopen */
	printf("Calling fopen()...\n");
	file = fopen("test1.txt", "r");
	if(file == NULL) 
		printf("fopen failed!\n");
	else
		printf("fopen succeded.\n");
	fclose(file);
	/* test1: fwrite */
	FILE *fp1 = fopen("test1.txt", "r");
	char s[] = "something to write...\n";
	printf("Calling fwrite()...\n");
	if(1*strlen(s) != fwrite(s,1,strlen(s),fp1)){
		printf("fwrite failed!\n");
		}
	else
		printf("fwrite succeded.\n");
	fclose(fp1);
	/* test1: open*/
	printf("Calling open()...\n");
	int fop2 = open("test1.txt", O_RDONLY);
	if(fop2 < 0)
		printf("open failed!\n");
	else
		printf("open succeded.\n");
	/* test1: write */
	printf("Calling write()...\n");
	char u[] = "something to write...\n";
	if(write(fop2,u,strlen(u)) != strlen(u)){
		printf("write failed!\n");
		}
	else
		printf("write succeded.\n");
	
	/* test2: open*/
	printf("Calling open()...\n");
	int fp2 = open("test2.txt", O_RDONLY);
	if(fp2 < 0) 
		printf("open failed!\n");
	else
		printf("open succeded.\n");
	/* test2: write */
	printf("Calling write()...\n");
	char t[] = "something to write...\n";
	if(write(fp2,t,strlen(t)) != strlen(t)){
		printf("write failed!\n");
		}
	else
		printf("write succeded.\n");
	/* test2: fopen */
	printf("Calling fopen()...\n");
	file = fopen("test2.txt", "r");
	if(file == NULL) 
		printf("fopen failed!\n");
	else
		printf("fopen succeded.\n");
	fclose(file);
	/* test2: fwrite */
	printf("Calling fwrite()...\n");
	FILE *fp3 = fopen("test2.txt", "r");
	char y[] = "something to write...\n";
	if(1*strlen(y) != fwrite(y,1,strlen(y),fp3)){
		printf("fwrite failed!\n");
		}
	else
		printf("fwrite succeded.\n");
	fclose(fp3);
}

#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_DIRECTORY "./aclog-test"

static int create_denied_samples(void)
{
	char path[128];
	FILE *file;
	int i;

	for (i = 0; i < 8; ++i) {
		if (snprintf(path, sizeof(path), TEST_DIRECTORY "/denied-%d.txt", i) < 0)
			return -1;
		file = fopen(path, "w");
		if (file == NULL)
			return -1;
		if (fclose(file) != 0 || chmod(path, 0000) != 0)
			return -1;
	}

	for (i = 0; i < 8; ++i) {
		(void)snprintf(path, sizeof(path), TEST_DIRECTORY "/denied-%d.txt", i);
		errno = 0;
		file = fopen(path, "r");
		if (file != NULL) {
			fprintf(stderr, "Expected permission denial for %s\n", path);
			(void)fclose(file);
		}
	}

	for (i = 0; i < 8; ++i) {
		(void)snprintf(path, sizeof(path), TEST_DIRECTORY "/denied-%d.txt", i);
		if (chmod(path, S_IRUSR | S_IWUSR) != 0)
			return -1;
	}
	return 0;
}

static int create_modification_samples(void)
{
	static const char first[] = "first version\n";
	static const char second[] = "second version\n";
	FILE *file = fopen(TEST_DIRECTORY "/modified.txt", "w+");

	if (file == NULL)
		return -1;
	if (fwrite(first, 1, strlen(first), file) != strlen(first) ||
	    fwrite(second, 1, strlen(second), file) != strlen(second)) {
		(void)fclose(file);
		return -1;
	}
	return fclose(file);
}

int main(void)
{
	if (mkdir(TEST_DIRECTORY, S_IRWXU) != 0 && errno != EEXIST) {
		perror("mkdir");
		return 1;
	}
	if (create_denied_samples() != 0) {
		perror("denied-file test setup");
		return 1;
	}
	if (create_modification_samples() != 0) {
		perror("modification test setup");
		return 1;
	}
	puts("Generated eight denied accesses and two modifications.");
	return 0;
}
