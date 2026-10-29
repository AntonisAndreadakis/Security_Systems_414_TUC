#define _GNU_SOURCE
#if 0 /* Original submission retained below for review. */
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


struct entry{ 
	char *userID;
	char *filename;
	char *date;
	char *time;
	char *open;
	char *action_denied;
	char *hash;  
	struct entry *next;
};

void usage(void){
	printf(
	       "\n"
	       "usage:\n"
	       "\t./acmonitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

struct node_users_activity{
	char *userID;
	int count;
	struct files_user_accessed *head;   
	struct node_users_activity *next;
};
struct files_user_accessed{
	char *filename;
	struct files_user_accessed *next;   
};

struct node *UserSinglyList;
struct node_users_activity *UserActivitySinglyList;

void insertUser(struct entry **userList, char *userID, char *filename, char *date, char *time, char *open, char * action_denied, char * hash){
	struct entry *newNode = NULL;
	struct entry *prev = *userList ;

	newNode = malloc(sizeof(struct entry));
	if (newNode == NULL){
		fprintf(stderr, "Failed to allocate memory");
		exit(0);
		}
	newNode->userID = malloc(strlen(userID) *sizeof(char));
	strcpy(newNode->userID,userID);
    
	newNode->filename = malloc(strlen(filename) *sizeof(char));
	strcpy(newNode->filename , filename);
    
	newNode->date = malloc(strlen(date) *sizeof(char));
	strcpy(newNode->date , date);
    
	newNode->time = malloc(strlen(time) *sizeof(char));
	strcpy(newNode->time , time);
    
	newNode->open = malloc(strlen(open) *sizeof(char));
	strcpy(newNode->open, open);
    
	newNode->action_denied = malloc(strlen(action_denied) *sizeof(char));
	strcpy(newNode->action_denied , action_denied);
    
	newNode->hash = malloc(strlen(hash) *sizeof(char));
	strcpy(newNode->hash , hash);
    
	newNode->next =  *userList;
	*userList = newNode;
}

void insertUserAct(struct node_users_activity **userActList, char *userID){
	struct node_users_activity *newNode = NULL;
    
	newNode = malloc(sizeof(struct node_users_activity));
	if (newNode == NULL){
		fprintf(stderr, "Failed to allocate memory");
		exit(0);
		}
	newNode->userID = malloc(strlen(userID) *sizeof(char));
	strcpy(newNode->userID,userID);

	newNode->head = NULL;
	newNode->count = 1;
    
	newNode->next =  *userActList;
	*userActList = newNode;
}

void insertFile(struct files_user_accessed **fileList, char*filename){
	struct files_user_accessed *newNode = NULL;
    
	newNode = malloc(sizeof(struct files_user_accessed));
	if (newNode == NULL){
		fprintf(stderr, "Failed to allocate memory");
		exit(0);
	}
	newNode->filename = malloc(strlen(filename) *sizeof(char));
	strcpy(newNode->filename,filename);
    
	newNode->next =  *fileList;
	*fileList = newNode;
}

void printUser(struct node * userList){
	while (userList != NULL){
		printf("Print:%s\t%s\t%s\t%s\t%s\t%s\t%s\n",userList->userID, userList->filename, userList->date,userList->time,userList->open , userList->action_denied,userList->hash);
		userList = userList->next;
		}
}

void list_unauthorized_accesses(struct node *userList){
	/* add your code here */	
	while (userList != NULL){
		if (!strcmp(userList->action_denied, "1")){
			printf("%s\n", userList->userID);
			}
		while (userActList != NULL){
			if (userList->count >= 7){
				printf("%s\n", userList->userID);
				}
			}
		userList = userList->next;
	}
}


void list_file_modifications(struct node *userList, char *filename){
	/* add your code here */
	while (userList != NULL){
		if (!strcmp(userList->filename, filename)){
			printf("%s\t", userList->userID);
			if (!strcmp(userList->open, "1") && !strcmp(userList->action_denied, "0")){
				/*User open the file for reading and the access is not denied : The file isn't modified*/
				printf("A\n");
			}
			else{
				if (userList->next!= NULL){
					if (!strcmp(userList->hash, "(null)")){
						/* Hash == null, we want to write and the access is not denied*/
						if (!strcmp(userList->open, "0") && !strcmp(userList->action_denied, "0")){
							printf("M\n");
							}
						}else if (!strcmp(userList->hash, userList->next->hash)){
							printf("A\n");
							}
						else{
							printf("M\n");
							}
						}
					else{
						if (!strcmp(userList->hash, "(null)")){
							/* Hash == null, we want to write and the access is not denied*/
							if (!strcmp(userList->open, "0") && !strcmp(userList->action_denied, "0")){
								printf("M\n");
								}
							}
							else{
								if (!strcmp(userList->open, "1") && !strcmp(userList->action_denied, "0")){
									printf("A\n");
									}
							else {
								printf("M\n");
								}
						}
					}
				}
			}
		userList = userList->next;
	}
}


int main(int argc, char *argv[]){
	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL){
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
		}
	/* add your code here */
	/* ... */
	
	int i = 0;
	char *logName;
	char *functionNum;
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	/* ... */
	UserSinglyList = NULL;
	UserActivitySinglyList= NULL;
	logName = argv[1];
	functionNum = argv[2];
	while((read = getline(&line, &len, log))!=-1){
		char *str[7];
		char *pch;
		pch = strtok(line, " ");
		int j = 0;
		while(pch!=NULL){
			str[j] = pch;
			pch = strtok(NULL, " ");
			j++;
			}        
		insertUser(&UserSinglyList,str[0],str[1],str[2],str[3],str[4],str[5],str[6]);       
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(UserSinglyList);
			break;
		case 'm':
			list_unauthorized_accesses(UserSinglyList, logName);
			break;
		case 'h':
			usage();
			break;
		default:
			usage();
			}
		}


	
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;
	
return 0;
}

#endif

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct user_stat {
	unsigned long uid;
	size_t modifications;
	int accessed;
	char **denied_files;
	size_t denied_count;
	size_t denied_capacity;
	struct user_stat *next;
};

struct log_entry {
	unsigned long uid;
	const char *file;
	int access_type;
	int denied;
	const char *fingerprint;
};

static void print_usage(FILE *output, const char *program)
{
	fprintf(output,
	        "Usage: %s -m\n"
	        "       %s -i <filename>\n"
	        "       %s -h\n",
	        program, program, program);
}

static struct user_stat *find_user(struct user_stat **head, unsigned long uid)
{
	struct user_stat *user;

	for (user = *head; user != NULL; user = user->next) {
		if (user->uid == uid)
			return user;
	}
	user = calloc(1, sizeof(*user));
	if (user == NULL)
		return NULL;
	user->uid = uid;
	user->next = *head;
	*head = user;
	return user;
}

static int add_denied_file(struct user_stat *user, const char *file)
{
	size_t i;
	char **resized;

	for (i = 0; i < user->denied_count; ++i) {
		if (strcmp(user->denied_files[i], file) == 0)
			return 0;
	}
	if (user->denied_count == user->denied_capacity) {
		size_t capacity = user->denied_capacity == 0 ? 8 : user->denied_capacity * 2;
		resized = realloc(user->denied_files, capacity * sizeof(*resized));
		if (resized == NULL)
			return -1;
		user->denied_files = resized;
		user->denied_capacity = capacity;
	}
	user->denied_files[user->denied_count] = strdup(file);
	if (user->denied_files[user->denied_count] == NULL)
		return -1;
	++user->denied_count;
	return 0;
}

static int parse_entry(char *line, struct log_entry *entry)
{
	char *fields[7];
	char *save = NULL;
	char *end;
	int i;

	for (i = 0; i < 7; ++i) {
		fields[i] = strtok_r(i == 0 ? line : NULL, "\t", &save);
		if (fields[i] == NULL)
			return -1;
	}
	fields[6][strcspn(fields[6], "\r\n")] = '\0';
	errno = 0;
	entry->uid = strtoul(fields[0], &end, 10);
	if (errno != 0 || *end != '\0')
		return -1;
	entry->file = fields[1];
	entry->access_type = (int)strtol(fields[4], &end, 10);
	if (*end != '\0' || entry->access_type < 0 || entry->access_type > 2)
		return -1;
	entry->denied = (int)strtol(fields[5], &end, 10);
	if (*end != '\0' || (entry->denied != 0 && entry->denied != 1))
		return -1;
	entry->fingerprint = fields[6];
	return 0;
}

static void free_users(struct user_stat *head)
{
	while (head != NULL) {
		struct user_stat *next = head->next;
		size_t i;
		for (i = 0; i < head->denied_count; ++i)
			free(head->denied_files[i]);
		free(head->denied_files);
		free(head);
		head = next;
	}
}

static int list_malicious(FILE *log)
{
	struct user_stat *users = NULL;
	struct user_stat *user;
	struct log_entry entry;
	char *line = NULL;
	size_t capacity = 0;
	int result = 0;

	while (getline(&line, &capacity, log) != -1) {
		if (parse_entry(line, &entry) != 0 || !entry.denied)
			continue;
		user = find_user(&users, entry.uid);
		if (user == NULL || add_denied_file(user, entry.file) != 0) {
			fprintf(stderr, "Out of memory\n");
			result = 1;
			break;
		}
	}
	if (result == 0) {
		printf("UID\tDENIED_DISTINCT_FILES\n");
		for (user = users; user != NULL; user = user->next) {
			if (user->denied_count > 7)
				printf("%lu\t%zu\n", user->uid, user->denied_count);
		}
	}
	free(line);
	free_users(users);
	return result;
}

static int list_modifications(FILE *log, const char *requested_file)
{
	struct user_stat *users = NULL;
	struct user_stat *user;
	struct log_entry entry;
	char target[PATH_MAX];
	char previous[65] = "";
	char *line = NULL;
	size_t capacity = 0;

	if (realpath(requested_file, target) == NULL) {
		if (snprintf(target, sizeof(target), "%s", requested_file) >= (int)sizeof(target)) {
			fprintf(stderr, "Filename is too long\n");
			return 1;
		}
	}
	while (getline(&line, &capacity, log) != -1) {
		if (parse_entry(line, &entry) != 0 || strcmp(entry.file, target) != 0)
			continue;
		user = find_user(&users, entry.uid);
		if (user == NULL) {
			fprintf(stderr, "Out of memory\n");
			free(line);
			free_users(users);
			return 1;
		}
		user->accessed = 1;
		if (entry.denied || strcmp(entry.fingerprint, "-") == 0)
			continue;
		if (entry.access_type == 2 && previous[0] != '\0' &&
		    strcmp(previous, entry.fingerprint) != 0)
			++user->modifications;
		(void)snprintf(previous, sizeof(previous), "%s", entry.fingerprint);
	}
	printf("UID\tMODIFICATIONS\n");
	for (user = users; user != NULL; user = user->next) {
		if (user->accessed)
			printf("%lu\t%zu\n", user->uid, user->modifications);
	}
	free(line);
	free_users(users);
	return 0;
}

int main(int argc, char **argv)
{
	const char *path = getenv("ACLOG_PATH");
	const char *file_to_scan = NULL;
	FILE *log;
	int option;
	int mode = 0;
	int result;

	if (path == NULL || path[0] == '\0')
		path = "./file_logging.log";
	opterr = 0;
	while ((option = getopt(argc, argv, "hmi:")) != -1) {
		switch (option) {
		case 'h':
			print_usage(stdout, argv[0]);
			return 0;
		case 'm':
			if (mode != 0) {
				print_usage(stderr, argv[0]);
				return 2;
			}
			mode = 'm';
			break;
		case 'i':
			if (mode != 0) {
				print_usage(stderr, argv[0]);
				return 2;
			}
			mode = 'i';
			file_to_scan = optarg;
			break;
		default:
			print_usage(stderr, argv[0]);
			return 2;
		}
	}
	if (mode == 0 || optind != argc) {
		print_usage(stderr, argv[0]);
		return 2;
	}
	log = fopen(path, "r");
	if (log == NULL) {
		fprintf(stderr, "Cannot open log file %s: %s\n", path, strerror(errno));
		return 1;
	}
	result = mode == 'm' ? list_malicious(log) : list_modifications(log, file_to_scan);
	if (fclose(log) != 0 && result == 0)
		result = 1;
	return result;
}
