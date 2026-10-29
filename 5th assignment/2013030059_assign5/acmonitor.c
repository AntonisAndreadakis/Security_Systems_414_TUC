#define _GNU_SOURCE

#if 0 /* Original assignment-5 submission retained below for review; not compiled. */

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
	/* allocate space for string + terminating NUL */
	node->file = malloc(strlen(filepath) + 1);
	if(node->file) strcpy(node->file, filepath);
	node->exists = exists;
	node->date = malloc(strlen(date) + 1);
	if(node->date) strcpy(node->date, date );
	node->time = malloc(strlen(time) + 1);
	if(node->time) strcpy(node->time, time);
	node->fingerprint = malloc(strlen(file_hash) + 1);
	if(node->fingerprint) strcpy(node->fingerprint, file_hash);
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
	size_t line_size = 0;
	ssize_t nread;

	/* get the first line (getline will allocate when line == NULL and line_size == 0) */
	nread = getline(&line, &line_size, fp);
	/* read while getline returns more than a newline (nread > 1) */
	while(nread != -1 && nread > 1){
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
		/* trim trailing newlines from tokens (safety) */
		for(int _i = 0; _i < 9; _i++){
			if(str[_i]){
				size_t _l = strlen(str[_i]);
				if(_l && str[_i][_l-1] == '\n')
					str[_i][_l-1] = '\0';
			}
		}
		//store to a single linked list:
		head = push_log(head, atoi(str[1]), atoi(str[2]), atoi(str[3]), str[4], atoi(str[5]), str[6], str[7], str[8]);
		//read again:
		nread = getline(&line, &line_size, fp);
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

#endif

/* Fixed implementation below, built on the Assignment 4 parser/format (see
 * ../../4th assignment/2013030059_assign4/acmonitor.c) and enriched with -v
 * and -e per the Assignment 5 brief. Problems fixed from the original above:
 *  - getopt string "hi:hv:m:e" made -m take an argument it should not.
 *  - 'k'/'lines' used before initialization in list_unauthorized_accesses()
 *    and the -e case.
 *  - list_unauthorized_accesses() used a per-pair threshold of 1 denied
 *    event instead of "more than 7 distinct denied files", and re-read the
 *    whole 7-space-separated-token log format that logger.c no longer
 *    writes (it writes 7 tab-separated fields; space-splitting a path with
 *    spaces, or the trailing "hour:min:sec" group, misaligned every field
 *    after it).
 *  - fileLists()/filesCreated() never used its "threshold" argument, and
 *    compared unpadded time strings ("%2d:%d:%d" vs a lexicographic "<"),
 *    which sorts "9:5:0" after "10:0:0".
 *  - print_encrypted() never checked that the original file was actually
 *    opened first, read its own already-NUL'd cleanPath[] with strtok("."),
 *    and could strcpy() past the fixed-size "files" buffer.
 *  - main() re-used the same FILE* across options without rewinding it, so
 *    a second flag after the first always "ran out" of log lines.
 */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define RECENT_WINDOW_SECONDS (20 * 60)

enum access_type { ACCESS_CREATE = 0, ACCESS_OPEN = 1, ACCESS_WRITE = 2 };

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
	time_t when; /* 0 if the timestamp could not be parsed */
};

static void print_usage(FILE *output, const char *program)
{
	fprintf(output,
	        "Usage: %s -m\n"
	        "       %s -i <filename>\n"
	        "       %s -v <number of files>\n"
	        "       %s -e\n"
	        "       %s -h\n",
	        program, program, program, program, program);
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

/* Parse one "uid\tpath\tYYYY-MM-DD\tHH:MM:SS\taccess\tdenied\tfingerprint"
 * record, as written by logger.c. */
static int parse_entry(char *line, struct log_entry *entry)
{
	char *fields[7];
	char *save = NULL;
	char *end;
	int i;
	struct tm when;

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

	memset(&when, 0, sizeof(when));
	if (strptime(fields[2], "%Y-%m-%d", &when) != NULL &&
	    strptime(fields[3], "%H:%M:%S", &when) != NULL) {
		when.tm_isdst = -1;
		entry->when = mktime(&when);
	} else {
		entry->when = (time_t)0;
	}
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

/* -m: distinct denied files per user, as Assignment 4 defines "malicious". */
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

/* -i <filename>: count fingerprint changes on writes to that (resolved) path. */
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
		if (entry.access_type == ACCESS_WRITE && previous[0] != '\0' &&
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

/* -v <threshold>: successful creations in the last 20 minutes, and whether
 * at least <threshold> of them happened (the ransomware's bulk-create step). */
static int list_recent_creations(FILE *log, long threshold)
{
	struct log_entry entry;
	char *line = NULL;
	size_t capacity = 0;
	time_t now = time(NULL);
	unsigned long count = 0;

	if (threshold < 0) {
		fprintf(stderr, "Threshold must not be negative\n");
		return 2;
	}
	while (getline(&line, &capacity, log) != -1) {
		if (parse_entry(line, &entry) != 0)
			continue;
		if (entry.denied || entry.access_type != ACCESS_CREATE)
			continue;
		if (entry.when == 0)
			continue;
		if (entry.when <= now && difftime(now, entry.when) <= RECENT_WINDOW_SECONDS)
			++count;
	}
	free(line);
	printf("Files created in the last 20 minutes: %lu\n", count);
	printf("Threshold reached: %s\n", count >= (unsigned long)threshold ? "yes" : "no");
	return 0;
}

/* -e: files the ransomware created by encrypting an original it had opened.
 * A match requires, for the same UID: a successful OPEN of "name", followed
 * later by a successful CREATE of "name.encrypt". */
struct opened_pair {
	unsigned long uid;
	char *path;
	struct opened_pair *next;
};

static int remember_open(struct opened_pair **head, unsigned long uid, const char *path)
{
	struct opened_pair *node = malloc(sizeof(*node));

	if (node == NULL)
		return -1;
	node->uid = uid;
	node->path = strdup(path);
	if (node->path == NULL) {
		free(node);
		return -1;
	}
	node->next = *head;
	*head = node;
	return 0;
}

/* Finds and unlinks the first (uid, path) match so one open cannot be
 * reused to "explain" more than one encrypted file. */
static int take_open(struct opened_pair **head, unsigned long uid, const char *path)
{
	struct opened_pair *curr = *head;
	struct opened_pair *prev = NULL;

	while (curr != NULL) {
		if (curr->uid == uid && strcmp(curr->path, path) == 0) {
			if (prev != NULL)
				prev->next = curr->next;
			else
				*head = curr->next;
			free(curr->path);
			free(curr);
			return 1;
		}
		prev = curr;
		curr = curr->next;
	}
	return 0;
}

static void free_opened(struct opened_pair *head)
{
	while (head != NULL) {
		struct opened_pair *next = head->next;
		free(head->path);
		free(head);
		head = next;
	}
}

static int list_encrypted(FILE *log)
{
	static const char suffix[] = ".encrypt";
	const size_t suffix_length = sizeof(suffix) - 1;
	struct opened_pair *opened = NULL;
	struct log_entry entry;
	char *line = NULL;
	size_t capacity = 0;
	unsigned long matches = 0;

	while (getline(&line, &capacity, log) != -1) {
		size_t file_length;

		if (parse_entry(line, &entry) != 0 || entry.denied)
			continue;
		if (entry.access_type == ACCESS_OPEN) {
			if (remember_open(&opened, entry.uid, entry.file) != 0) {
				fprintf(stderr, "Out of memory\n");
				free(line);
				free_opened(opened);
				return 1;
			}
			continue;
		}
		if (entry.access_type != ACCESS_CREATE)
			continue;
		file_length = strlen(entry.file);
		if (file_length <= suffix_length ||
		    strcmp(entry.file + file_length - suffix_length, suffix) != 0)
			continue;
		{
			char original[PATH_MAX];
			size_t original_length = file_length - suffix_length;

			if (original_length >= sizeof(original))
				continue;
			memcpy(original, entry.file, original_length);
			original[original_length] = '\0';
			if (take_open(&opened, entry.uid, original)) {
				printf("uid:\t%lu\toriginal:\t%s\tencrypted:\t%s\n",
				       entry.uid, original, entry.file);
				++matches;
			}
		}
	}
	free(line);
	free_opened(opened);
	printf("Encrypted: %lu\n", matches);
	return 0;
}

int main(int argc, char **argv)
{
	const char *path = getenv("ACLOG_PATH");
	const char *file_to_scan = NULL;
	long threshold = 0;
	FILE *log;
	int option;
	int mode = 0;
	int result;
	char *end;

	if (path == NULL || path[0] == '\0')
		path = "./file_logging.log";
	opterr = 0;
	while ((option = getopt(argc, argv, "hmi:v:e")) != -1) {
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
		case 'v':
			if (mode != 0) {
				print_usage(stderr, argv[0]);
				return 2;
			}
			mode = 'v';
			errno = 0;
			threshold = strtol(optarg, &end, 10);
			if (errno != 0 || *end != '\0' || end == optarg || threshold < 0) {
				fprintf(stderr, "Invalid threshold: %s\n", optarg);
				return 2;
			}
			break;
		case 'e':
			if (mode != 0) {
				print_usage(stderr, argv[0]);
				return 2;
			}
			mode = 'e';
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
	switch (mode) {
	case 'm':
		result = list_malicious(log);
		break;
	case 'i':
		result = list_modifications(log, file_to_scan);
		break;
	case 'v':
		result = list_recent_creations(log, threshold);
		break;
	case 'e':
		result = list_encrypted(log);
		break;
	default:
		result = 2;
		break;
	}
	if (fclose(log) != 0 && result == 0)
		result = 1;
	return result;
}
