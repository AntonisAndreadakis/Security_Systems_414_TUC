#define _GNU_SOURCE
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

