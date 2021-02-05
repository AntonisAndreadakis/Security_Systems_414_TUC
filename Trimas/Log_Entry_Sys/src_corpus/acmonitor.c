#include "myLib.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

void list_unauthorized_accesses(FILE* log)
{
	int count;
	char* logName;
	char* line = NULL;
	size_t len = 0;
	ssize_t read;
	char action;

	// save everything in a stack, for second operation
	while((read = getline(&line, &len, log)) != -1)
	{
		count = 0;
		char* str[7];
		char* element;
		element = strtok(line, "\t");
		int i = 0;

		for(; i<7; i++)
		{
			str[i] = element;
			element = strtok(NULL, "\t");
		}
		if((strcmp(str[5], "1")==0))
		{
			count++;
			size_t len2=0;
			ssize_t read2;
			char* str2[7];
			char* line2 = NULL;
			while((read2 = getline(&line2, &len2, log))!=-1)
			{
				char* element2;
				element2 = strtok(line2,"\t");
				int j = 0;
				for(; j<7; j++)
				{
					str2[j] = element2;
					element2 = strtok(NULL, "\t");
				}

				if((strcmp(str[0],str2[0])==0) && (strcmp(str2[5],"1")==0) && strcmp(str[1],str2[1])!=0)
				{
					count++;
				}
			}

			if(count >= 7)
			{
				printf("User %s unseccesfully tried to open seven or more files.\n",str[0]);
				break;
			}
		}
	}
}

void list_file_modifications(FILE *log, char *file_to_scan)
{

	char* line = NULL;
	size_t len = 0;
	ssize_t read;

	char given_path[1024];
	realpath(file_to_scan, given_path);

	char line_hashes[20];
	char* prev_hash = NULL;
	int i;
	int access_counter = 0, counter = 0;
	while((read = getline(&line, &len, log)) != -1)
	{
		char* element;
		char* str[7];
		element = strtok(line, "\t");
		i = 0;

		while( i < 7)
		{
			str[i] = element;
			element = strtok(NULL, "\t");
			i++;
		}

		if((strcmp(str[1], given_path)) == 0)
		{
			if((strcmp(str[4],"0") == 0) && (strcmp(str[5],"0") == 0))
			{
				access_counter++;
			}

			if(prev_hash != NULL)
			{
				if((strcmp(prev_hash, str[6])) != 0)
				{
					counter++;
				}

				else if((strcmp(str[4],"1")) == 0 && (strcmp(str[5],"0")) == 0)
				{
					access_counter++;
				}
			}

			prev_hash = str[6];
			char* line2 = NULL;
			size_t len2 = 0;
			ssize_t read2;
			char* str2[7];

			while((read2 = getline(&line2, &len2, log)) != -1)
			{
				char* element2;
				element2 = strtok(line2,"\t");
				int k = 0;

				while(k < 7)
				{
					str2[k] = element2;
					element2 = strtok(NULL,"\t");
					k++;
				}

				if((strcmp(str2[1], given_path) == 0) && (strcmp(prev_hash,str2[6]) != 0))
				{
					if((strcmp(str2[3],"1")==0) && (strcmp(str2[5],"0")==0))
					{
						counter++;
					}
					prev_hash = str2[6];
					break;
				}
				else if((strcmp(str2[1], given_path)==0) && (strcmp(prev_hash, str2[6])==0) && (strcmp(str2[5],"0")==0))
				{
					access_counter++;
				}
			}
		}
		printf("User with id:%s, accessed file: %d, and modified it: %d.\n", str[0], access_counter, counter);
	}
	
	return;
}

int main(int argc, char *argv[])
{

	int ch;
	char* logName;
	char* line = NULL;
	size_t len = 0;
	ssize_t read;
	char action;

	FILE *log;
	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, argv[2]);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}

	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
