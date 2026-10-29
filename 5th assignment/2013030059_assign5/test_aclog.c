#include <stdio.h>

#if 0 /* Original assignment-5 submission retained below for review; not compiled. */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {

	FILE *file;
	int i;
	size_t bytes;
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
			bytes = fwrite(filenames[i], sizeof(filenames[i]), 1, file);
			fclose(file);
		}
	}

	/* add your code here */
	file = fopen("test1.txt", "r");
	file = fopen("test2.txt", "r");
	file = fopen("test3.txt", "r");
	fclose(file);
	// test1: fwrite
	file = fopen("test1.txt", "w");
	char s[] = "something to write\n";
	printf("\nCalling fwrite()...\n");
	fwrite(s,1,sizeof(s),file);
	fclose(file);
	file = fopen("test1.txt", "w+");
	fwrite(s,1,sizeof(s),file);
	fclose(file);
	printf("\nfwrite() succeded.\n");
	// test1: open
	printf("\nCalling open()...\n");
	int fop2 = open("test1.txt", O_RDONLY);
	if(fop2 < 0){
		printf("\nopen() failed!\n");
		exit(1);
		}
	else
		printf("\nopen() succeded.\n");
	printf("\nCalling open()...\n");
	int fp3 = open("test1.txt", O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR);
	if(fp3 < 0){
		printf("\nopen() failed!\n");
		exit(1);
		}
	else
		printf("\nopen() succeded.\n");
	close(fop2);
	close(fp3);
	//append mode:
	printf("Calling the fopen() function..\n");
	FILE *fallo = fopen("test.txt","a");
	if(!fallo){
		printf("fopen() returned NULL\n");
		//return 1;
	}
	else
		printf("fopen() succeeded\n");
	fclose(fallo);
	char file_names[10][6] = {"file0", "file1", "file2", "file3", "file4", "file5", "file6", "file7", "file8", "file9"};
	for (i = 0; i < 10; i++) {
		file = fopen(file_names[i], "r");
		if (file == NULL)
			printf("\nfopen error\n");
		else
			printf("\nfopen() succeded.\n");
		FILE *fd = fopen(file_names[i], "w");
		fwrite(s,1,sizeof(s),fd);
		fclose(file);
	}
	printf("\nCalling fopen()...\n");
	file = fopen("test.txt", "r");
	if(!file){
		printf("fopen() returned NULL\n");
		//return 1;
	}
	else
		printf("fopen() succeeded\n");
	printf("\nCalling fopen()...\n");
	file = fopen("test1.txt", "r");
	if(!file){
		printf("fopen() returned NULL\n");
		//return 1;
	}
	else
		printf("fopen() succeeded\n");
	printf("\nCalling fopen()...\n");
	file = fopen("test2.txt", "r");
	if(!file){
		printf("fopen() returned NULL\n");
		//return 1;
	}
	else
		printf("fopen() succeeded\n");
	fclose(file);
return 0;
}

#endif

/* Fixed implementation below. The original mixed undeclared-identifier bugs
 * (S_IRUSR/S_IWUSR without <sys/stat.h>) with filenames ("file0".."file9",
 * "file_0".."file_9", "test.txt", "test1.txt", "test2.txt") that collided
 * with real submission fixtures sitting in the same directory, so running it
 * in-place could silently overwrite coursework files. This version confines
 * every fixture to its own "./aclog-test" directory and additionally
 * generates the creation-burst and open-then-encrypt events that acmonitor's
 * -v and -e modes are meant to detect, alongside the -m (denied) and -i
 * (modified) fixtures Assignment 4's test already covered.
 */

#include <errno.h>
#include <stdlib.h>
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

/* -v: creates ten throwaway files; combined with the eight denied-file
 * creations and modified.txt above, -v 5 reports "yes" and -v 50 "no". */
static int create_recent_batch(void)
{
	char path[128];
	FILE *file;
	int i;

	for (i = 0; i < 10; ++i) {
		if (snprintf(path, sizeof(path), TEST_DIRECTORY "/burst-%d.txt", i) < 0)
			return -1;
		file = fopen(path, "w");
		if (file == NULL)
			return -1;
		if (fclose(file) != 0)
			return -1;
	}
	return 0;
}

/* -e: open the original, then create "<original>.encrypt" - the pattern
 * acmonitor -e looks for. */
static int create_encrypted_sample(void)
{
	static const char data[] = "plaintext\n";
	FILE *original = fopen(TEST_DIRECTORY "/secret.txt", "w");

	if (original == NULL)
		return -1;
	if (fwrite(data, 1, strlen(data), original) != strlen(data)) {
		(void)fclose(original);
		return -1;
	}
	if (fclose(original) != 0)
		return -1;

	original = fopen(TEST_DIRECTORY "/secret.txt", "r");
	if (original == NULL)
		return -1;
	if (fclose(original) != 0)
		return -1;

	FILE *encrypted = fopen(TEST_DIRECTORY "/secret.txt.encrypt", "w");
	if (encrypted == NULL)
		return -1;
	if (fwrite(data, 1, strlen(data), encrypted) != strlen(data)) {
		(void)fclose(encrypted);
		return -1;
	}
	return fclose(encrypted);
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
	if (create_recent_batch() != 0) {
		perror("recent-creation batch setup");
		return 1;
	}
	if (create_encrypted_sample() != 0) {
		perror("encrypted-sample setup");
		return 1;
	}
	puts("Generated eight denied accesses, two modifications, ten recent "
	     "creations and one encrypted file.");
	return 0;
}
