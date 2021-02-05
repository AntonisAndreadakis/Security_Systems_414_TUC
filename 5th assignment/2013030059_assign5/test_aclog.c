#include <stdio.h>
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
