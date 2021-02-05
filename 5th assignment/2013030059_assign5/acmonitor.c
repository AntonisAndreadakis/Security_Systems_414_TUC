#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct entry{ 
	int uid;
	int access_type;
	int action_denied;
	int exists;
	char *date;
	char *time;
	char *file;	
	char *fingerprint;  
	struct entry *next;
};

void usage(void){
	printf("\n"	"usage:\n"	"./acmonitor \n"
		"Options:\n"
		"-m, 			Prints malicious users\n"
		"-i <filename>,		Prints table of users that modified the file <filename> and the type of modifications\n"
		"-v <threshold>,	Prints files created in a certain time.\n"
		"-e,			Prints files encrypted.\n"
		"-h,			Help message\n\n");
	exit(1);
}

/*	In systems where "sizeof(int) == 32", integers  will fit in 12 bytes when converted to string. We define that as <INT_SIZ>.	*/
#ifndef INT_SIZ
#define INT_SIZ 12		
#endif

/*	 - When in Ubuntu tm_year + 1900 will produce the proper year.
	 - Using function handles that field change as well.	*/
struct tm *get_time(){
	struct tm *retVal;
	time_t rawtime;
	//get time and adjust on local settings:
	time(&rawtime);
	retVal = localtime(&rawtime);
	//fix calibration issue by adding 1900 to the result:
	retVal->tm_year += 1900;
	retVal->tm_mon++;
	return retVal;
}

void print_log(struct entry *log){
	if(log)
		fprintf(stdout, "uid: %-5d filename: %s File Exists (0/1): %d Date: %s Time:%s\n", log->uid, log->file, log->exists, log->date, log->time);
	else
		fprintf(stdout, "Empty!\n");
}

/*	Create nodes of "struct entry" and push into the right position in the given "struct entry *" list.
	-arg1: 		head of the log list.
	-arg2-9: 	values for the newly created node.
	Returns:	Always the head of the list.	*/
struct entry *push_log(struct entry *head, int uid, int action_type, int action_status, char *filepath, int exists,char *date, char *time, char *file_hash){

	struct entry *node = (struct entry *)malloc(sizeof(struct entry));
	struct entry *curr = head;
	//initialize content:
	node->uid = uid;
	node->access_type = action_type;
	node->action_denied = action_status;
	node->file = malloc(strlen(filepath));
	strcpy(node->file, filepath);
	node->exists = exists;
	node->date = malloc(strlen(date));
	strcpy(node->date, date );
	node->time = malloc(strlen(time));
	strcpy(node->time, time);	
	node->fingerprint = malloc(strlen(file_hash));
	strcpy(node->fingerprint, file_hash);	
	node->next = NULL;
	//one element list:
	if(head == NULL)
		return node;
	//seek the end of the list:
	while(curr->next != NULL)
		curr = curr->next;
	//append node:
	curr->next = node;
    return head;
}

struct entry *read_log(FILE *fp, int *a){

	struct entry *head = NULL;
	char *line = NULL;
	size_t line_size;
	
	//get the first line:
	line_size = getline(&line, &line_size, fp);
	//read with readline:
	while((int)line_size > 1){
		*a = *a + 1;		
		//save tokens:
		char *str[9];
		//use " " as delimiter:
		char *token = strtok(line, " ");
		int i=0;
		while(token != NULL){
			str[i] = token;
			//again:
			token = strtok(NULL, " ");
			i++;
			}
		//store to a single linked list:
		head = push_log(head, atoi(str[1]), atoi(str[2]), atoi(str[3]), str[4], atoi(str[5]), str[6], str[7], str[8]);		
		//read again:
		line_size = getline(&line, &line_size, fp);
	}
	return head;
}



void list_users(struct entry *log, int threshold){

	struct entry *prev = log;
	int count;
	int malicious[0xFFF];
	int m_count = 0;	
	
	while(prev){
		count = 0;
		struct entry *curr = prev;
		while(curr){
			if((curr->uid == prev->uid ) && (curr->action_denied == 1)){
				count++;
			}
			curr = curr->next;
		}
		//prompt user if actual occurence:
		if(count >= threshold){
			int found = 0;
			for(int i = 0; i < m_count; i++){
				if(malicious[i] == prev->uid)
					found = -1;
			}
			if(found == 0){
				malicious[m_count] = prev->uid;
				m_count++;
			}
		}		
		prev = prev->next;
	}	
	if(!m_count)
		fprintf(stdout,"No malicious users.\n");
	else{
		fprintf(stdout,"Malicious users:\n");
		for(int i = 0; i < m_count; i++){
			fprintf(stdout, "uid:\t%d\n", malicious[i]);
		}
	}
}

void list_unauthorized_accesses(FILE *log){
	int k;
	struct entry *head = read_log(log, &k);
	list_users(head,1);
return;
}

/*	List the user who modified a file specified by "char *target_file" and count accesses.	*/
void list_mods(struct entry *log, char *target_file){

	struct entry *curr = log;
	int count;
	int m_count = 0;
	int attempts[0xFFF];
	int modificants[0xFFF];
	char *init_hash = NULL;
	
	//find the first file occurence:
	while((curr != NULL ) && (strcmp(target_file, curr->file) != 0)){
		curr = curr->next;
	}
	if(!curr){
		printf("File does not exist!\n");
		return;
	}
	//remember initial hash:
	init_hash = curr->fingerprint;	
	//if seen again, the file might be modified:
	while(curr){
		//if same file and the file is acutally altered:
		if((strcmp(init_hash, curr->fingerprint) != 0) && strcmp(curr->file, target_file) == 0){
			//existance flag:
			int found = 0;
			for(int i = 0; i < m_count; i++){
				//if already there, increase access count:
				if(modificants[i] == curr->uid){
					attempts[i] += 1;
					found  = 1;
				}
			}
			//first occurence, we record:
			if(found == 0){
				modificants[m_count] = curr->uid;
				attempts[m_count] = 1;
				m_count++;
			}		
		}
		//move next log:
		curr = curr->next;	
	}		
	//prompt before exiting:
	if(!m_count)
		fprintf(stdout,"No modifications found.\n");
	else{
		fprintf(stdout,"Users who modified \"%s\":\n\n", target_file);
		fprintf(stdout, "uid\t times modified:\t\n\n");
		for(int i = 0; i < m_count; i++){
			fprintf(stdout, "%-5d\t%10d\n", modificants[i], attempts[i]);
		}
	}
}
void list_file_modifications(FILE *log, char *file_to_scan){
	/* add your code here */
	int a = 0;
	struct entry *head = read_log(log, &a);
	list_mods(head, file_to_scan);
return;
}

/*	Now we create a list of files made in time range of (start_time - threshold, start_time). Arguments:
	-arg1: a pointer to head of the log list.
	-arg2: the time range to search between, should be in minutes [0, 60].
	-arg3: a threshold to define minimum file number.	*/
void fileLists(struct entry *log, int timeRange, int threshold){

	unsigned int files_created = 0;
	//catch the head pointer:
	struct entry *curr = log;
	//get the time and express it with list contents:
	struct tm *t = get_time();
	//this is actually pre-compile-time allocation:
	char *init_time = (char *)malloc(3*INT_SIZ);  //hour, minute, sec = 3 elements
	char *curr_date = (char *)malloc(3*INT_SIZ);  //year, month, dat = 3 elements
	//adjust initial time:
	t->tm_min =(t->tm_min - timeRange)%60;
	//adjusting values in time range:
	if(t->tm_min < 0){
		t->tm_min += 60;
		t->tm_hour -= 1;
	}
	//convert to string(easier than doing the opossite), format should be same as on logger.c:
	sprintf(init_time, "%2d:%d:%d", t->tm_hour, t->tm_min, t->tm_sec); 
	sprintf(curr_date, "%d-%d-%d", t->tm_year, t->tm_mon, t->tm_mday);
	printf("Initiate time: %s Current date: %s\n", init_time, curr_date);
	//itterate through the log list:
	while(curr){	
		//if same date and specified time range and file was created from scratch:
		if((strcmp(curr_date, curr->date) == 0) && (strcmp(init_time, curr->time) < 0) && (curr->access_type == 0)){
			//just count events:
			files_created++;
		}
		curr = curr->next;
	}
	fprintf(stdout, "Info: %d files were created in the last %d minutes.\n", files_created, timeRange);	

	free(init_time);
	free(curr_date);
}

void filesCreated(FILE *log, int i){
	int howLong = 20;
	int a = 0;
	struct entry *head = read_log(log, &a);
	fileLists(head, howLong, i);
}


void print_encrypted(struct entry *log, int a){
	//offset in array.
	int offset = 0;
	//start from the initial log:
	struct entry *curr = log;
	//assume max file name size:
	size_t file_len = 256;
	//what we wish to locate:
	char *target_suffix = "encrypt";
	//allocate space for n, different files:
	char *files = (char *)malloc(sizeof(char )*a*file_len);
	
	while(curr){
		int in_list = 0;
		char fPath[0xFFF]; 
		char cleanPath[0xFFF];
		
		//remember the access type: 
		if(strstr(curr->file ,target_suffix) && curr->access_type == 0){
			strcpy(fPath, curr->file);
			size_t t_len = 0;
			//delimiter is set to "."
			char *tok = strtok(fPath, ".");
						
			//tokenized entity:
			while(tok != NULL && strcmp(tok, target_suffix) != 0){
				//copy:
				memcpy(cleanPath + t_len, tok, strlen(tok));
				//append delimiter:
				*(cleanPath + strlen(cleanPath)) = '.';
				//fix lenght issues
				t_len += strlen(tok);
				t_len += sizeof(char);
				//move on:
				tok = strtok(NULL, ".");	
			}
			//chop the last delim:
			*(cleanPath + strlen(cleanPath) -1) = '\0';
			//avoid duplicates:
			for(int i = 0; i < offset; i++){
				if(strcmp(cleanPath, files + file_len*i) == 0)
					in_list = 1;
			}
			//append in structure..
			if(!in_list){
				strcpy(files + file_len*offset, cleanPath);
				offset++;
			}
		}
		//move on:
		curr = curr->next;
		//reusabillity:
		memset(cleanPath, '\0', 0xFFF);
	}

	fprintf(stdout, "Encrypted: %d Total: %d\n",offset, a);	

	if(offset)
		for(int i = 0; i < offset; i++)
			printf("File:\t%s\n", files + file_len*i);
	
}

int main(int argc, char *argv[]){
	int ch;
	int lines;
	struct entry *head;
	FILE *log;
	if (argc < 2)
		usage();
	
	log = fopen("./file_logging.log", "r");
	if (log == NULL){
		printf("Error opening log file \"%s\"\n", "file_logging.log");
		return 1;
		}
	
	while ((ch = getopt(argc, argv, "hi:hv:m:e")) != -1) {
		switch (ch) {	
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		case 'v':
			filesCreated(log, atoi(optarg));
			break;
		case 'e':
			head = read_log(log, &lines);
			print_encrypted(head, lines);
			break;
		default:
			usage();
			}
		}
	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	fclose(log);
	argc -= optind;
	argv += optind;
	
return 0;
}

