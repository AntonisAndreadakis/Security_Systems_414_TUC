#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16
#define BUF_SIZ 512


/* Utility function prototypes */


void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
unsigned char *readFile(char *fPath, unsigned long *len);
void writeFile(char *fPath, unsigned char *data, unsigned long len);
void handleError(void );

/* Actual encryption functions */

void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/*
	
	UTILITY FUNCTIONS.
	
*/


/*
	Prints info concerning an OpenSSL error..

*/
void handleError(void )
{
	ERR_print_errors_fp(stderr);
}


/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
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
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void check_args(char *input_file, char *output_file, unsigned char *password,  int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a given password.
   Arguments:	
   					<char *password>: A password under which the key gets generated.
   					<char *key>: 	  Points the location in which the generated key gets to be stored.
   					<char *iv>:		  Pointer to an alphabet which randomises the encryption [such as str1 == str2 but key1 != key2].
   					<char *bit_mode>: The actual bits of the AES-ECB to be produced.
   	Notes: 
   					- <char *bit_mode> is guaranteed to be 128 or 256.
					- sha1 hashing is applied.
					- no "salt" is used.
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode)
{



	//defining parameters.
	const unsigned char *salt = NULL;
	const EVP_CIPHER *cipher;
	const EVP_MD *hash = EVP_get_digestbyname("sha1");


	//adjustin cipher with respect on bit mode.
	(bit_mode == 128) ? (cipher = EVP_get_cipherbyname("aes-128-ecb")): (cipher = EVP_get_cipherbyname("aes-256-ecb"));



	//generating key and error handling.

	if (EVP_BytesToKey(cipher, hash, salt, (unsigned char *)password, strlen((char *)password), 1, key, iv) == 0)
	{
		handleError();
		fprintf(stderr, "Error in key generation..\n");
		exit(-1);
	}
	
	

}


/*

	ENCRYPTION FUNCTIONS.


*/


/*
 * Encrypts the data
 */
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{


	//parameters
	EVP_CIPHER_CTX *context; 
	const EVP_CIPHER *cipher;
	int encryptionLength, cipherLength;

	//init. the context.
	context =  EVP_CIPHER_CTX_new();

	//adjusting cipher with respect on bit mode.
	(bit_mode == 128) ? (cipher = EVP_get_cipherbyname("aes-128-ecb")): (cipher = EVP_get_cipherbyname("aes-256-ecb"));

	//be brave, apply assertion. [remove if feeling sure about the results]
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(context) == (bit_mode % 8));


	//init. encryption process and error handling.
	if(!EVP_EncryptInit_ex(context, cipher, NULL, key, iv))
	{
		fprintf(stderr, "Error upon context initialization [Encryption]\n");
		exit(-1);
	}


	//updating the encryption, error handling as well.

	if(!EVP_EncryptUpdate(context, ciphertext, &encryptionLength, plaintext, plaintext_len))
	{
		EVP_CIPHER_CTX_free(context);
		fprintf(stderr, "Error upon updating context [Encryption]\n");
		exit(-1);
	}

	cipherLength = encryptionLength;

	//finalising encryption process with error handling as always.
	if(!EVP_EncryptFinal_ex(context, ciphertext + encryptionLength, &encryptionLength))
	{
		handleError();
		EVP_CIPHER_CTX_free(context);
		fprintf(stderr, "Error upon finalising the encryption process [Encryption]\n");
		exit(-1);


	}

	cipherLength += encryptionLength;
	

	//releasing sensitive info from memory.
	EVP_CIPHER_CTX_free(context);


}


/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_len = 0;
	
	//parameters
	EVP_CIPHER_CTX *context; 
	const EVP_CIPHER *cipher;
	int encryptionLength;

	//init. the context.
	context =  EVP_CIPHER_CTX_new();

	//getting the cipher with respect on the bit mode.
	(bit_mode == 128) ? (cipher = EVP_get_cipherbyname("aes-128-ecb")): (cipher = EVP_get_cipherbyname("aes-256-ecb"));

	//be brave, apply assertion. [remove if feeling sure about the results]
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(context) == (bit_mode % 8));



	//init. decryption process and error handling.
	if(EVP_DecryptInit_ex(context, cipher, NULL, key, iv) == 0)
	{
		fprintf(stderr, "Error upon context initialization [Decryption]\n");
		exit(-1);
	}


	//updating the decryption, error handling as well.

	if(!EVP_DecryptUpdate(context, plaintext, &encryptionLength, ciphertext, ciphertext_len))
	{
		EVP_CIPHER_CTX_free(context);
		fprintf(stderr, "Error upon updating context [Decryption]\n");
		exit(-1);
	}

	//update count.
	plaintext_len = encryptionLength;
	

	//finalising decryption process with error handling as always.
	if(!EVP_DecryptFinal_ex(context, plaintext + encryptionLength, &encryptionLength))
	{
		handleError();
		EVP_CIPHER_CTX_free(context);
		fprintf(stderr, "Error upon finalising the decryption process [Decryption]\n");
		exit(-1);


	}

	//finalize length.
	plaintext_len += encryptionLength;


	//releasing sensitive info from memory.
	EVP_CIPHER_CTX_free(context);


	//return the actual size of the decrypted text.
	return plaintext_len;
}


/*
 * Generates a CMAC.
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key,unsigned char *cmac, int bit_mode)
{
	//parameters
	CMAC_CTX *context; 
	const EVP_CIPHER *cipher;
	size_t signLength;

	//initialize context.
	context = CMAC_CTX_new();	


	//asjuting cipher with respect on bit mode.
	(bit_mode == 128) ? (cipher = EVP_get_cipherbyname("aes-128-cbc")): (cipher = EVP_get_cipherbyname("aes-256-cbc"));

	//DO NOT FOR NO REASON SELECT ECB AES IF IN TUC OR UOC-CSD, IVE DONE THAT SHIT AND TOOK ME 7 DAYS TO DISCOVER IT.


	//initalize with error handling
	if(!CMAC_Init(context, key, bit_mode/8, cipher, NULL))
	{
		fprintf(stderr, "Error upon cmac initialization [Signing]\n");
		CMAC_CTX_free(context);
		exit(-1);
	}
	//update to include the date,with error handling
	if(!CMAC_Update(context, data, data_len))
	{
		fprintf(stderr, "Error upon data encapsulation [Signing]\n");
		CMAC_CTX_free(context);
		exit(-1);
	}


	/*
		Finalize.
		<CMAC_Final()> writes 16 bytes at minimum in case of success, practically that might be 22 or even more.
		Therefore cmac's size should be restricted.

	*/
	if(!CMAC_Final(context, cmac, &signLength))
	{
		fprintf(stderr, "Error upon data finalisation [Signing]\n");
		CMAC_CTX_free(context);
		exit(-1);
	}

	//append termination, handle the event of overflow upon initialization, make it printable..
	*(cmac + BLOCK_SIZE) = '\0';

	//delete sensitive stuff.
	CMAC_CTX_free(context);
	

}


/*
 * Verifies a CMAC's validity, by wrapper check.
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	//byte-wise comparison of cmac's
	return (memcmp(cmac1,cmac2,BLOCK_SIZE) == 0);



}



/* Utility functions */



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

*/
void writeFile(char *fPath, unsigned char *data, unsigned long len)
{

	//initialise a file pointer;
	FILE *fp;
	

	// opt will determine whether bytes or ASCII will be written.

	fp = fopen(fPath, "wb");

	if(!fp)
	{
		fprintf(stderr, "File not found, tool will terminate now..\n" );
		exit(-1);
	}

	///write as a stream and not character wise.
	fwrite(data, sizeof(unsigned char) ,(size_t)len, fp);

	fclose(fp);
}



/* TODO Develop your functions here... */



/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	//usefull when holding input, output.

	unsigned char *input = NULL;
	unsigned char *output = NULL;
	unsigned long inpLen = 0;
	unsigned long outpLen = 0;




	unsigned char globalKey[256];
	unsigned char iv[256]; //this can be filled with a random pool.
	unsigned char *ciphertext;
	unsigned char *origCMAC;
	unsigned char *givenCMAC;
	unsigned char *tmp;






	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:f")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'f':
			//debug sign.

			op_mode = 4;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	


	/// Free the input buffer, then do stuff.

	if(input_file != NULL)
		input= readFile(input_file, &inpLen);
	if(!input)
	{
		fprintf(stderr, "Empty data set given, exiting now..\n");
		exit(EXIT_FAILURE);
	}
	


	/*

	Initialize the library, no need to be done in version above OpenSSL 1.1.0
	Uncomment if running versions below 1.1.0
	
	*/
	//OpenSSL_add_all_algorithms(); 
	

	/* Keygen from password */

	
	keygen(password, globalKey, iv, bit_mode);


	/* Operate on the data according to the mode */

	switch(op_mode)
	{
		case 0:


				/*
					Encrypt then write on file specified.	
				
				*/



				//allocate appropriate space.

				outpLen = inpLen - (inpLen % BLOCK_SIZE) + BLOCK_SIZE;
				output = (unsigned char *)malloc(outpLen);

				//encrypt..
				encrypt(input, inpLen, globalKey, iv, output, bit_mode);
				
				

				//write output on the specified file as bytes.
				writeFile(output_file, output, outpLen);

				break;
		case 1:
				
				/*
					Decrypt then write on file specified.
					Will not work if encrypted msg has a CMAC sign.	
				
				*/

				outpLen = inpLen - (inpLen % BLOCK_SIZE) + BLOCK_SIZE;
				output = (unsigned char *)malloc(outpLen);
				outpLen = decrypt(input, inpLen, globalKey, iv, output, bit_mode);
			

				//write output as plaintext [ASCII].
				writeFile(output_file, output, outpLen);

				break;

		case 2:

				/*
					Encrypt then sign with a 16-byte cmac.
					Write on file specified.

				*/
				
				outpLen = inpLen - (inpLen % BLOCK_SIZE) + BLOCK_SIZE;
				output = (unsigned char *)malloc(outpLen);

				//encrypting input..
				encrypt(input, strlen((const char *)input), globalKey, iv, output, bit_mode);


				//allocating space for both encryted and cmac.
				ciphertext = (unsigned char *)malloc(strlen((const char *)output) + BLOCK_SIZE);

				
				//copying encrypted..
				memcpy(ciphertext, output, outpLen);

				
				//allocating space for cmac [BLOCK_SIZE = 16 bytes] + 1 for terminating character.			
				tmp = (unsigned char *)malloc(sizeof(unsigned char )*BLOCK_SIZE + 1);


				/*

					Generating the cmac.
					What took me days to understand is that the CMAC gets generated upon the original/non-ecrypted msg and NOT the encrypted.
					<strlen()> will work here since it has to do with ASCII text.


				*/
				gen_cmac(input, strlen((const char *)input), globalKey, tmp, bit_mode);
				

				//copying cmac on stream..

				memcpy(ciphertext + strlen((const char *)output), tmp, BLOCK_SIZE);

				
				//writing stream on file.
				writeFile(output_file, ciphertext, strlen((const char *)ciphertext));
			
			

				// free up resources..

				free(ciphertext);
				free(tmp);


				
				break;

		case 3:

				/*
					Decrypting then veryfing the CMAC sign by checking the wrappers.
					
				*/

				

				
				//calculating space for input..
				outpLen = inpLen - (inpLen % BLOCK_SIZE) + BLOCK_SIZE;
				output = (unsigned char *)malloc(outpLen);
				
				//decrypt ciphertext only.
				outpLen = decrypt(input, inpLen - BLOCK_SIZE, globalKey, iv, output, bit_mode);
				
				//make it printable and compatitible with strlen()..
				*(output + outpLen) = '\0';


				
				//allocating space, copying the CMAC from input.
				givenCMAC = (unsigned char *)malloc(BLOCK_SIZE);
				memcpy(givenCMAC, input + inpLen - BLOCK_SIZE, BLOCK_SIZE);

				//hey we need it to be printable, I dont like hex..
				*(givenCMAC + BLOCK_SIZE) = '\0';


				
				//generate our own CMAC to compare with given.

				origCMAC = (unsigned char *)malloc(BLOCK_SIZE);

				gen_cmac(output,strlen((const char *)output),globalKey, origCMAC, bit_mode);

				
				//remove comment block if testing.
				/*


				printf("%s\n", origCMAC);
				printf("%s\n", givenCMAC);

				*/


				//check cmacs and prompt user...
				if(!verify_cmac(origCMAC, givenCMAC))
					printf("Unable to verify given message..\n");
				else
				{
					printf("Message verified, writing decrypted on file now..\n");
					writeFile(output_file, output, outpLen);
				}


				
				break;

		default:
				fprintf(stderr, "Invalid option [opt_mode]..\n");	
				break;
	
     }





     
    
		

	/* Clean up */
	
	free(input_file);
	free(output_file);
	free(password);
	free(input);
	free(output);


	/* END */
	return 0;
}
