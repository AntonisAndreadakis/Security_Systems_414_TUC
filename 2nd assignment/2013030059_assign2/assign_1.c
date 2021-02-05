#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16 //IV's size
#define CMAC_SIZE 16 //same as IV's
#define TRUE 1
#define FALSE 0

/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char **, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, unsigned char **, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */
void writeFile(char *f, unsigned char *t, int l, int m);
unsigned char *read_plaintext(char *);


/* SOME GLOBAL VARIABLES: */
int cipher_length, ssize;
int b = 0;
unsigned char *gkey = NULL;

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void print_hex(unsigned char *data, size_t len){
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
void print_string(unsigned char *data, size_t len){
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
void usage(void){
	printf(	"\n"
		"Usage:\n"
		"    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
		"    assign_1 -h\n");
	printf(	"\n"
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
		"In order to debug, write '1' (without ' ') at the end, as last argument to enable debug mode.\n");//added debug mode
		
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void check_args(char *input_file, char *output_file, unsigned char *password, int bit_mode, int op_mode){
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
 * Generates a key using a password
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode){

	/* TODO Task A */
	
	const EVP_CIPHER *cipher;
	const EVP_MD *hash_func = NULL;
	const unsigned char *var1 = NULL;
	//select cipher mode and key size:
	if(bit_mode == 128)
		cipher = EVP_get_cipherbyname("AES-128-ECB");
	else if(bit_mode == 256)
		cipher = EVP_get_cipherbyname("AES-256-ECB");
	else {
		fprintf(stderr, "ERROR in cipher parameter!\n");
		exit(1);
		}
	//select hash function before keygen:
	gkey = malloc(bit_mode/8);
	hash_func = EVP_get_digestbyname("SHA1");
	//convert password's bytes to key:
	if(EVP_BytesToKey(cipher,hash_func,var1,(unsigned char *)password,strlen((char *)password),1,gkey,iv) == 0){
		fprintf(stderr, "ERROR in EVP_BytesToKey!\n");
		exit(1);
	}
	if(b)
		print_hex(gkey, bit_mode/8);
}


/*
 * Encrypt the data
 */
void encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char **ciphertext, int bit_mode){

	/* TODO Task B */
	EVP_CIPHER_CTX *context;
	int var2_length;
	int var2_final_len;
	const EVP_CIPHER *var3;
	unsigned char *var4;

	if(b){
		printf("Start Encryption.\n");
		print_hex(plaintext, plaintext_len);
		}
	if(bit_mode == 128){
		var3 = EVP_get_cipherbyname("AES-128-ECB");
		}
	else if(bit_mode == 256)
		var3 = EVP_get_cipherbyname("AES-256-ECB");
	else {
		fprintf(stderr, "ERROR in cipher parameter!\n");
		exit(1);
		}
	if(b)
		printf("Before Init.\n");
	//create new encrypted context:
	//EVP_CIPHER_CTX_init(context);
	context = EVP_CIPHER_CTX_new();
	if(b)
		printf("Before Init.\n");
	//check for correct mode and key size:
	if(EVP_EncryptInit_ex(context,var3,NULL,key,iv)==0){
		fprintf(stderr, "ERROR in EVP_EncryptInit_ex during encryption!\n");
		exit(1);
		}
	//update ciphertext:
	var4 = malloc(plaintext_len+BLOCK_SIZE);
	if(b){
		printf("Before Update.\n");
		printf("%d\n", plaintext_len);
		}
	if(EVP_EncryptUpdate(context,var4,&var2_length,plaintext,plaintext_len)==0){
		fprintf(stderr, "ERROR in EVP_EncryptUpdate during encryption!\n");
		exit(1);
		}
	if(b)
		printf("Before Final.\n");
	//finish encryption:
	if(EVP_EncryptFinal_ex(context,&var4[var2_length],&var2_final_len)==0){
		fprintf(stderr, "ERROR in EVP_EncryptFinal_ex during encryption!\n");
		exit(1);
		}
	if(b)
		printf("Before cipher_malloc.\n");
	cipher_length = var2_length + var2_final_len;
	*ciphertext = malloc(cipher_length);
	memcpy(*ciphertext, var4, cipher_length);
	if(b){
		printf("Cipher length: %d\n", cipher_length);
		print_hex(*ciphertext,cipher_length);
		printf("End of Encryption.\n");
		}
	//free:
	EVP_CIPHER_CTX_cleanup(context);
}


/*
 * Decrypt the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int cipher_length, unsigned char *key, unsigned char *iv, unsigned char **plaintext, int bit_mode){
	int plaintext_len;
	int plainLen;
	int plainLenFinal = 16;
	unsigned char *var5;

	plaintext_len = 0;
	/*TODO Task C */
	EVP_CIPHER_CTX *context;
	const EVP_CIPHER *var6;
	if(b){
		printf("Starting Decryption...\n");
		print_hex(ciphertext,cipher_length);
		}
	if(bit_mode == 128)
		var6 = EVP_get_cipherbyname("AES-128-ECB");
	else if(bit_mode == 256)
		var6 = EVP_get_cipherbyname("AES-256-ECB");
	else{
		fprintf(stderr, "ERROR in cipher parameter!\n");
		exit(1);
		}
	if(b)
		printf("Before Decryption.\n");
	//check for correct mode and key size:
	//EVP_CIPHER_CTX_init(context);
	context = EVP_CIPHER_CTX_new();
	if(EVP_DecryptInit_ex(context,var6,NULL,key,iv)==0){
		fprintf(stderr, "ERROR in EVP_DecryptInit_ex during decryption!\n");
		exit(1);
		}
	if(b)
		printf("Before malloc.\n");
	var5 = malloc(cipher_length+BLOCK_SIZE);
	//update plaintext:
	if(b)
		printf("Before Decryption Update.\n");				
	if(EVP_EncryptUpdate(context,var5,&plainLen,ciphertext,cipher_length)==0){
		fprintf(stderr, "ERROR in EVP_EncryptUpdate during encryption!\n");
		exit(1);
		}
	if(b){
		printf("Before Decryption Finish.\n");
		printf("%d \n", plainLen);
		print_string(var5,plainLen);
		}
	//finish decryption:
	if(EVP_EncryptFinal_ex(context,&var5[plainLen],&plainLenFinal)==0){
		fprintf(stderr, "ERROR in EVP_EncryptFinal_ex during encryption!\n");
		exit(1);
		}
	plaintext_len = plainLen + plainLenFinal;
	*plaintext = malloc(plaintext_len);
	memcpy(*plaintext, var5, plaintext_len);
	if(b)
		print_string(*plaintext,plaintext_len);
	//free:
	EVP_CIPHER_CTX_cleanup(context);
	
	if(b)		
		printf("End of Decryption.\n");
		
	return plaintext_len;
}


/*
 * Generate a CMAC
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, unsigned char *cmac, int bit_mode){

	/* TODO Task D */
	int kSize;
	const EVP_CIPHER *var7;
	size_t cSize;
	
	if(b){
		printf("Generating CMAC...\n");
		print_string(data,data_len);
	}
	//create cmac context:
	CMAC_CTX *var8 = CMAC_CTX_new();
	//key size:
	if(bit_mode == 128){
		var7 = EVP_get_cipherbyname("AES-128-ECB");
		kSize = 16;
		}
	else if(bit_mode == 256){
		var7 = EVP_get_cipherbyname("AES-256-ECB");
		kSize = 32;
		}
	else{
		fprintf(stderr, "ERROR in cipher parameter!\n");
		exit(1);
		}
	if(CMAC_Init(var8,key,kSize,var7,NULL)==0){
		fprintf(stderr, "ERROR in CMAC_INIT!\n");
		exit(1);
		}
	//update CMAC:
	if(CMAC_Update(var8,data,data_len)==0){
		fprintf(stderr, "ERROR in CMAC_INIT!\n");
		exit(1);		
		}
	//finish CMAC:
	if(CMAC_Final(var8,cmac,&cSize)==0){
		fprintf(stderr, "ERROR in CMAC_INIT!\n");
		exit(1);
		}
	//free:
	CMAC_CTX_free(var8);
	kSize = -1;
	var7 = 	NULL;
	if(b)
		printf("Generating CMAC ended.\n");
}


/*
 * Verify a CMAC
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2){
	int verify;
	/* TODO Task E */
	//CMAC attached at the end of message has fixed size
	//So decrypt message and store CMAC
	//Calculate again CMAC likewise generating it
	//Finally compare the 2 CMAC
	for(verify=0;verify<CMAC_SIZE;verify++){
		if(cmac1[verify]!=cmac2[verify])
			return FALSE;		
		}
	return TRUE;
}



/* TODO Develop your functions here... */

	//***** 1st function **********//
	//helper function for CMAC verification:
int verifyCmac(int bitMode, int mesLen, char *o, unsigned char *m){
	int plainLen;
	unsigned char *c1;
	unsigned char *c2;
	unsigned char *cText;
	unsigned char *pText;
	
	if(b){
		printf("Starting CMAC verification...\n");
		printf("%d\n", mesLen);
		}
	//CMAC attached at the end of message has fixed size:
	c1 = malloc(CMAC_SIZE);
	cText = malloc(mesLen-CMAC_SIZE);//get "clean" text
	pText = malloc(mesLen-CMAC_SIZE);//same here

	memcpy(c1,&m[mesLen-CMAC_SIZE],CMAC_SIZE);
	
	if(b)
		print_hex(c1,CMAC_SIZE);
	memcpy(cText,m,mesLen-CMAC_SIZE);
	//So decrypt message and store CMAC:
	plainLen = decrypt(cText,mesLen-CMAC_SIZE,gkey,NULL,&pText,bitMode);
	//Calculate again CMAC likewise generating it:
	c2 = malloc(CMAC_SIZE);
	gen_cmac(pText,strlen((const char *)pText),gkey,c2,bitMode);
	if(b){
		print_hex(c2,CMAC_SIZE);
		print_hex(c1,CMAC_SIZE);
		}
	if(b)
		printf("CMAC verification ended.\n");
	//call verify_cmac in order to compare CMACs:
	if(verify_cmac(c1,c2)){
		writeFile(o,pText,plainLen,0);//function "writeFile" is defined below
		return TRUE;
		}
	return FALSE;
}
	//***** 2nd function **********//
	//write to file:
void writeFile(char *f, unsigned char *t, int l, int m){
	if(b)
		printf("Start writing to file...\n");
	FILE *fp;
	if(m){
		if(b)
			printf("Writing bytes...");
		fp = fopen(f,"wb");
		}
	else{
		if(b)
			printf("Writing text...");
		fp = fopen(f,"w");
		}
	if(fp==NULL){
		fprintf(stderr,"ERROR writing to file!\n");
		exit(-1);
		}
	fwrite(t,sizeof(unsigned char),l,fp);
	fclose(fp);
	if(b)
		printf("Writing to file ended.\n");	
}


	//***** 3rd function **********//
	//read plaintext from file:
unsigned char *read_plaintext(char *f){
	int c;
	unsigned int i;
	unsigned char *s;
	FILE *n;
	n = fopen(f,"r");
	i=0;
	s = malloc(ssize*(sizeof(char)));
	c = fgetc(n);
	while(c!=EOF){
		if(i>ssize){
			ssize+=ssize;
			s = realloc(s,ssize);
		}
		s[i++] = c;
		c = fgetc(n);
	}
	if(i==0)
		return NULL;
	s[i] = '\0';
	fclose(n);
	return s;
}

	//***** 4th function **********//
	//read bytetext from file:
int readBytetext(char *f, unsigned char **buf){
	FILE *fp;
	int fLen;
	fp = fopen(f,"rb");
	if(fp==NULL){
		fprintf(stderr,"ERROR writing to file!\n");
		exit(-1);
		}
	fseek(fp,0,SEEK_END);
	fLen = ftell(fp);
	rewind(fp);
	*buf = malloc(fLen+1);
	fread(*buf,fLen,1,fp);
	fclose(fp);
	return fLen;
}




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
int main(int argc, char **argv){
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;
	ssize = 512;
	//extra arguments:
	int var1;
	int var2;
	unsigned char *readvar1 = NULL;
	unsigned char *cText = NULL;
	unsigned char *pText = NULL;
	unsigned char *CMAC = NULL;
	unsigned char *shorted = NULL;

	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
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
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */
	//Debug:
	if(argc==11 && atoi(argv[argc-1])==1){
		printf("Debuging...\n");
		b = 1;
		}
	/* Initialize the library */
	OpenSSL_add_all_algorithms();

	/* Keygen from password */
	keygen(password,NULL,NULL,bit_mode);

	/* Operate on the data according to the mode */
	switch(op_mode){
	/* encrypt */
	case 0:
		if(b)
			printf("OP_MODE: 0, Encrypting...\n");
		readvar1 = read_plaintext(input_file);
		encrypt(readvar1,strlen((const char *)readvar1),gkey,NULL,&cText,bit_mode);
		if(b)
			print_hex(cText,cipher_length); //use global variable 'cipher_length' for argument
		writeFile(output_file,cText,cipher_length,1);//use global variable 'cipher_length' for argument
		if(b){
			printf("Encrypted file is being decrypted right away...\n");
			var1 = decrypt(cText,cipher_length,gkey,NULL,&pText,bit_mode);
		}
		break;
	/* decrypt */
	case 1:
		if(b)
			printf("OP_MODE: 1, Decrypting...\n");
		var2 = readBytetext(input_file,&cText);
		var1 = decrypt(cText,var2,gkey,NULL,&pText,bit_mode);
		//write mode 0:
		writeFile(output_file,pText,var1,0);
		break;
	/* sign */
	case 2:
		if(b)
			printf("OP_MODE: 2, Signing...\n");
		readvar1 = read_plaintext(input_file);
		CMAC = malloc(CMAC_SIZE);
		gen_cmac(readvar1,strlen((const char *)readvar1),gkey,CMAC,bit_mode);
		encrypt(readvar1,strlen((const char *)readvar1),gkey,NULL,&cText,bit_mode);
		shorted = malloc(cipher_length+CMAC_SIZE);
		//copy cipher text:
		memcpy(shorted,cText,cipher_length);
		//copy cipher text's cmac:
		memcpy((shorted+cipher_length),CMAC,CMAC_SIZE);
		//write mode 1:
		writeFile(output_file,shorted,cipher_length+CMAC_SIZE,1);
		break;
	/* verify */
	case 3:
		if(b)
			printf("OP_MODE: 3, Verifying...\n");
		var2 = readBytetext(input_file,&cText);
		if(verifyCmac(bit_mode,var2,output_file,cText)==0){
			printf("Verified.\n");
			}
		else
			printf("Verification failed!\n");
		break;
	default:
		printf("OP_MODE not 0 - 3!\n");
	}
	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
