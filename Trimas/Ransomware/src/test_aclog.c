#include "myLib.h"

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	int j = 0;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	
	for (i = 0; i < 10; i++) {

		chmod(filenames[i%5], S_ISUID);
		file = fopen(filenames[i], "w");

		if (file == NULL) 
			printf("fopen error\n");
		
		else 
		{
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
		
		chmod(filenames[i], S_IRUSR);
		file = fopen(filenames[i], "r");
		
		if (file == NULL) 
			printf("fopen error\n");
		
		else 
		{
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}

	for(; j < 4; j++)
	{
		for (i = 0; i < 10; i++)
		{
			file = fopen(filenames[i], "r");
		}
	}
		
}