#include "myLib.h"

struct entry {

	char *uid; /* user id (positive integer) */
	char *access_type; /* access type values [0-2] */
	char *action_denied; /* is action denied values [0-1] */

	char *date; /* file access date */
	char *time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	struct entry *next;

};

struct entry* stackOfUsers;

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
		   "-e, Prints all the files that were encrypted by the ransomware.\n"
		   "-v <number of files>, Prints the total number of files created in the last 20 minutes.\n"
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

void insertUser(struct entry** list, char* id, char* file, char* date, char* time, char* access_type, char* action_denied, char* fingerprint)
{
	struct entry *newNode = NULL;
    struct entry *prev = *list ;

    newNode = malloc(sizeof(struct entry));

    if(newNode == NULL)
    {
    	fprintf (stderr, "Corrupted memory.\n");
    	exit(0);
    }

    newNode->uid = malloc(strlen(id) * sizeof(char));
    strcpy(newNode->uid,id);

    newNode->file = malloc(strlen(file) * sizeof(char));
    strcpy(newNode->file,file);

    newNode->date = malloc(strlen(date) * sizeof(char));
    strcpy(newNode->date,date);

    newNode->time = malloc(strlen(time) * sizeof(char));
    strcpy(newNode->time,time);

    newNode->access_type = malloc(strlen(access_type) * sizeof(char));
    strcpy(newNode->access_type,access_type);

    newNode->action_denied = malloc(strlen(action_denied) * sizeof(char));
    strcpy(newNode->action_denied,action_denied);

    newNode->fingerprint = malloc(strlen(fingerprint) * sizeof(char));
    strcpy(newNode->fingerprint, fingerprint);

    newNode->next =  *list;
    *list = newNode;
}

void printUser(struct entry * userList)
{
    while (userList != NULL){
        printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n",userList->uid, userList->file, userList->date,userList->time,userList->access_type , userList->action_denied,userList->fingerprint);
        userList = userList->next;
    }
}

void checkRecentFiles(FILE* log, int limit)
{
	char* line;
	size_t len;
	ssize_t read;
	int i = 0;

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

		if(strcmp(str[4],"0")==0)
		{
			insertUser(&stackOfUsers, str[0],str[1],str[2],str[3],str[4],str[5],str[6]);
		}
	}

	time_t tmp = time(NULL);
	struct tm tm = *localtime(&tmp);
	int counter = 0;

	while(stackOfUsers != NULL)
	{
		int year = atoi(strtok(stackOfUsers->date, "-"));
		int month = atoi(strtok(NULL, "-"));
		int day = atoi(strtok(NULL, "-"));

		int hour = atoi(strtok(stackOfUsers->time, ":"));
		int minute = atoi(strtok(NULL, ":"));
		int second = atoi(strtok(NULL, ":"));

		struct tm userTime;

		userTime.tm_sec = second;
		userTime.tm_min = minute;
		userTime.tm_hour = hour;
		userTime.tm_mday = day;
		userTime.tm_mon = month - 1;
		userTime.tm_year = year - 1900;
		userTime.tm_isdst = 0;

		time_t now = mktime(&tm);
		time_t userTm = mktime(&userTime);
		double wanted = difftime(now, userTm) / 60;

		if(wanted < 20)
		{
			counter++;
		}

		stackOfUsers = stackOfUsers->next;
	}

	if(counter >= limit)
	{
		printf("In the last 20 minutes %d files were created.\n", counter);
	}

	return;
}

int searchFile(struct entry* list, char* file)
{
	struct entry* tmp = list;

	while(tmp != NULL)
	{
		if(strcmp(tmp->file, file) == 0)
		{
			return 1;
		}
		tmp = tmp->next;
	}

	return 0;
}

void findEncryptedFiles(FILE* log)
{
	int count;
	char* line = NULL;
	size_t len = 0;
	ssize_t read;
	char action;
	int decision;
	struct entry* stackOfFiles = NULL;

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

		size_t filename_length = strlen(str[1]);
		size_t suffix_length = strlen(".encrypt");
		char* tmp = str[1] + filename_length - suffix_length;

		if(strcmp(".encrypt",tmp) == 0)
		{
			decision = searchFile(stackOfFiles, str[1]);

			if(decision == 0)
			{
				insertUser(&stackOfFiles, str[0],str[1],str[2],str[3],str[4],str[5],str[6]);
			}
		}
	}

	while(stackOfFiles != NULL)
	{
		printf("%s\n", stackOfFiles->file);
		stackOfFiles = stackOfFiles->next;
	}
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

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:v:me")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, argv[2]);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'v':
			checkRecentFiles(log, atoi(argv[2]));
			break;
		case 'e':
			findEncryptedFiles(log);
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
