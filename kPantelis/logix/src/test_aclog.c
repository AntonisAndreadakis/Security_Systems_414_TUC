#include <stdio.h>
#include <string.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};



	//definetlly waiting for denial here [NON EXISTENT], [LOG]
	file = fopen("skata.txt", "r");

	//won't get here unless i change "r" with "w+" [NO LOG]
	///if(file != NULL)
		//bytes = fwrite(filenames[7], 1, strlen(filenames[7]), file);

	//definettly waiting for denial here [rwx is closed via chmod]. [LOG]
	file = fopen("nono.txt", "r");
	


	//This should be created if not there [LOG]
	file = 	fopen("loutsos.txt","a");

	//this should work [LOG] [new hash as well]
	if(file != NULL)
		bytes = fwrite(filenames[7], 1, strlen(filenames[7]), file);

	fclose(file);
	



	/* example source code */
	
	/*
	
		10 open logs and 10 write logs should be created.
		Format:
				open log <file i> [EMPTY HASH]
				write log <file i> [CONTENT HASH]


	*/

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");


		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


}
