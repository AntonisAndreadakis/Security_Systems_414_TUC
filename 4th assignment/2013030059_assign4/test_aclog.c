#include <stdio.h>
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
