#include "utils.h"
#ifndef BUF_SIZ
#define BUF_SIZ 10000
#endif

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
 */
void print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message in a kinda nice manner.
 */
void usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_3 -g \n" 
	    "    assign_3 -i in_file -o out_file -k key_file [-d | -e]\n" 
	    "    assign_3 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -k    path    Path to key file\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -g            Generates a keypair and saves to 2 files\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*

 * Checks the validity of the arguments given
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode


 */
void check_args(char *input_file, char *output_file, char *key_file, int op_mode)
{
	if ((!input_file) && (op_mode != 2)) {
		printf("Error: No input file!\n");
		usage();
	}

	if ((!output_file) && (op_mode != 2)) {
		printf("Error: No output file!\n");
		usage();
	}

	if ((!key_file) && (op_mode != 2)) {
		printf("Error: No user key!\n");
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}

/*
	Parses and reads the content of a file, specified by <char *fPath>.
	Arguments:
				<char *fPath>:			full path of the file to be read.
				<unsigned long *len>: 	pointer to a location, whre the size of data in bytes will be stored.
	Returns:
				Data read as an <unsigned char *> [a form of string in C].
*/

unsigned char *readFile(char *fPath, unsigned long *len)
{
	FILE *fp;
	long fileLen = 0;
	

	//allocate some space on a buffer.
	unsigned char *data = (unsigned char *)malloc(sizeof(unsigned char )*BUF_SIZ + 1);


	//open the file, via the file pointer.

	fp  = fopen(fPath, "rb");
	
	//error handling on dummy file location.
	if(fp == NULL)
	{
		fprintf(stderr, "Error on opening file, tool will terminate now..\n" );
		exit(EXIT_FAILURE);
	}

	//estimate the length.
	fseek(fp, 0, SEEK_END);

	//unsafe yet useful for our cause.
	fileLen = ftell(fp);

	//set on beginning of file.
	rewind(fp);

	//read the first character.
	char ch = getc(fp);
	int charCount = 0;


	/*

		Checking for EOF [ch != EOF] will work on normal ASCII files.
		For reading the encrypted this won't work cause encrypted chars might contain EOF [0xffff] under some OS's.
		So it is prefered to check for file length via the estimation of ftell() even if ftell() is partially unsafe [especially under Windows].

	*/
	while(charCount != fileLen)
	{
		
		//re-allocate if needed.
		if(charCount >= BUF_SIZ)
			data = realloc(data, (charCount + 1)*sizeof(unsigned char));

		//counter incrementation and storage.
		data[charCount] = ch;
		charCount++;

		//read next char.
		ch = getc(fp);



	}
	
	//some error handling and then read.
	if(!data)
	{
		fprintf(stderr, "Error on initializing memory, tool will terminate now..\n" );
		exit(EXIT_FAILURE);
	}



	//append termination
	*(data + charCount) = '\0';

	//inform about the size
	*len = charCount;

	//avoid leaks.
	fclose(fp);



	return data;



}





/*
	
	Writes data in an output file.

	Arguments:
				<char *fPath>:			full path of the file to be filled.
				<unsigned long *len>: 	pointer to a location, where the size of data in bytes will be retrieved.
	Returns:
				None.
	Note:
				<unsigned long len>: should not be NULL, should have a valid length.

*/
void writeFile(char *fPath, void *data, unsigned long len)
{

	//initialise a file pointer;
	FILE *fp;
	

	// opt will determine whether bytes or ASCII will be written.

	fp = fopen(fPath, "w");

	if(!fp)
	{
		fprintf(stderr, "File not found, tool will terminate now..\n" );
		exit(-1);
	}

	///write as a stream and not character wise.
	fwrite(data, sizeof(unsigned char) ,(size_t)len, fp);

	fclose(fp);
}


/*

	Reads the encrypted file as an 0-255 (unsighned char *) quantity.
	This technique will work for encrypted files with total (ciphertext) size less than BUF_SIZ bytes.
	Args:

		<char * fPath>:	The full path of the file.
		<int *len>:		Pointer to be informed with the actual size of the file as taken from <fread()>.

	Returns:

		The ciphertext gained as a string.
	Note:
		-	Probably bad practice, will be changed with fd and POSIX safe guidelines sometime.. [ftello, fseeko, fd usage]
		-	If in "real-world" prefer I/O that compiles with POSIX guidelines and use file descriptors instead.
		- 	Do not try on Windows or IDE's.


*/


unsigned char* readEncrypted(char *fPath, int *len)
{


	FILE* fp = fopen(fPath, "r");
	

	if (fp == NULL)
		fprintf(stderr, "Unable to read the encrypted file..\n");


	//read on buffer..
	char* source = (char*)malloc((BUF_SIZ+1)*sizeof(char));
	size_t actual_len = fread(source, sizeof(char), BUF_SIZ, fp);
	
	//avoid leaks between syscalls..

	fclose(fp);
	

	//purified will be returned.
	char* buffer = (char*)malloc((actual_len)*sizeof(char));
	memcpy(buffer, source, actual_len);
	

	//free temporary buffer

	free(source);

	//inform about size.
	*len = (int)actual_len;

	
	//the purified one get's to survive.
	return (unsigned char*)buffer;
}



/*

	Writes a key (public/private) in a file specified by <char *loc>.
	Args:

			<size_t prefix>:	Key prefix (usually called n).
			<size_t postfix>:	Key postfix (aka e or d)
			<char *loc>:		Path to output file.



*/


void writeKey(size_t prefix, size_t postfix, char *loc)
{
	FILE *fp = fopen(loc, "w");

	if(fp == NULL)
	{
		fprintf(stderr,"Unable to write the key..\n");
		exit(-1);
	}

	//write all at once..
	fwrite(&prefix, 1, sizeof(size_t), fp);
	fwrite(&postfix, 1, sizeof(size_t), fp);

	//avoid leaks.

	fclose(fp);
}


/*

	
	Writes the ciphertext as an array of <sizeof(size_t)> quantities in a file.
	Args:

		<char *fPath>:	The full path of the file.
		<char *data>:	Data to be written.
		<int len>: 		The length of the data to be written [usually this would be sizeof(char)*sizeof(size_t)]
	
	Notes:
		- Writing all at once is a high risk proccess.
		- Do not use in "real world" apps.

*/


void writeEncrypted(char *fPath, size_t *data,int len)
{
	FILE *fp = fopen(fPath,"w");

	if(!fp){
		fprintf(stderr, "Unable to write encrypted..\n");
		exit(-1);
	}

	//write all at once..
	fwrite(data, sizeof(size_t) ,len, fp);
	

	fclose(fp);
}