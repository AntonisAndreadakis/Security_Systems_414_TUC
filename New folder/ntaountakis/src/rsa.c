#include "rsa.h"
#include "utils.h"


/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	size_t *primes;
	size_t table[limit+1];

	for(int i=0; i<=limit; i++){
		table[i] = 1; 
		if (i<2)
			table[i] = 0;
	}

	for (int i=2; i<=sqrt(limit); i++){
		if (table[i] == 1){ 
			int count = 0; 
			for (int j=pow(i, 2); j<=limit; j=pow(i, 2)+count*i){
				table[j] = 0; 
				count++; 
			}
		}
	}
	int pr_i = 0;
	//size_t *primes_tmp = (size_t*)malloc(limit*sizeof(size_t));
	for (int i=2; i<=limit; i++){
		if(table[i] == 1)
			pr_i++;
		
	}
	primes = (size_t*)malloc(pr_i*sizeof(size_t));
	int pr_j = 0; 
	for (int i=2; i<=limit; i++){
		if(table[i] == 1){
			primes[pr_j] = i; 
			printf("%d ", i);
			pr_j++;
		} 
	}
	printf("\n");
	
	//memcpy(primes, primes_tmp, pr_i*sizeof(size_t));
	*primes_sz = pr_i; 
	return primes;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{

	for(int i=1; i <= a && i <= b; ++i)
    {
        if(a%i==0 && b%i==0)
            return i;
    }
	return -1; 
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n, size_t* primes, int primes_size)
{
	size_t e = 0;

	for (int i=0; i<primes_size; i++){
		e = primes[i];
		if(((e > 3)&&(e<fi_n)) && (gcd(e, fi_n) == 1)){
		//if(((e%fi_n)!=0) && (gcd(e, fi_n) == 1))
			return e; 
		}

	}
	return -1;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */

size_t
mod_inverse(size_t a, size_t b)
{
	a=a%b;
	for (int i=1; i<b; i++){
		if ((a*i)%b == 1)
			return i; 
	}
	return -1; 
}

/*
size_t
mod_inverse(size_t a, size_t b)
{
	size_t x, y; 
	int extgcd;

	extgcd = extended_eucl(a, b, &x, &y);
	if (extgcd != 1){
		printf("Modular inverse not found!\n");
		exit(0);  
	}
	return (x%b + b)%b;
}

int extended_eucl(size_t a, size_t b,size_t *x, size_t *y){
 
    if (a == 0)  
    {  
        *x = 0;
		*y = 1;  
        return b;  
    }  
  
    size_t x1, y1;
    int gcd = extended_eucl(b%a, a, &x1, &y1);  
    
    *x = y1 - (b/a) * x1;  
    *y = x1;  
  
    return gcd;  
}
*/
void choose_from_pool(size_t* pool, int pool_size, size_t *num1, size_t *num2){
	
	int indx1, indx2; 
	srand(time(0));
	indx1=rand()%(pool_size-1);
	indx2=rand()%(pool_size-1);
	while(indx1==indx2)
	{
 		indx2=rand()%pool_size-1;
	}

	*num1 = pool[indx1];
	*num2 = pool[indx2];
}

void write_key(size_t num1, size_t num2 ,char* key_type){
	FILE* fp = fopen(key_type, "w"); 
	if (fp == NULL){
		printf("Unable to create file.\n");
		return; 
	}
	
	fwrite(&num1, 1, sizeof(num1), fp);
	fwrite(&num2, 1, sizeof(num2), fp);
	
	
	fclose(fp);
}

unsigned char* read_file(char* file_name, int *file_size){
	FILE* fp = fopen(file_name, "r");
	if (fp == NULL)
		return 0; 
	
	char* source = (char*)malloc((MAXBUFLEN+1)*sizeof(char));
	size_t newLen = fread(source, sizeof(char), MAXBUFLEN, fp);
	fclose(fp);
	
	char* buffer = (char*)malloc((newLen)*sizeof(char));
	memcpy(buffer, source, newLen);
	
	free(source);
	*file_size = (int)newLen;
	return (unsigned char*)buffer;
}

void write_file(size_t* text, char* path, int textsize){
	FILE* fp = fopen(path, "w"); 
	if (fp == NULL){
		printf("Unable to create file.\n");
		return; 
	}
	
	for (int i=0; i<textsize; i++){
		fwrite(&text[i], 1, sizeof(text[i]), fp);
	}

	fclose(fp);
}

void write_plaintext(unsigned char* text, char* path, int textsize){
	FILE* fp = fopen(path, "w"); 
	if (fp == NULL){
		printf("Unable to create file.\n");
		return; 
	}
	
	for (int i=0; i<textsize; i++){
		fwrite(&text[i], 1, sizeof(text[i]), fp);
	}

	fclose(fp);
}

size_t mod_pow(size_t base, size_t expn, size_t md){
	size_t result = 1; 

	// if md==1 exit... 

	for (int i=0; i<expn; i++){
		result = (size_t)((result * base)%md); 
	}
	return result; 
}

size_t* 
encode(unsigned char *plaintext, int file_size, size_t n, size_t d){
	
	size_t* ciphertext; 
	ciphertext = (size_t*)malloc(file_size*sizeof(size_t));
	for(int i=0; i<file_size; i++){
		//powl((size_t)plaintext[i],d);
		ciphertext[i] = mod_pow((size_t)plaintext[i], d, n);			
		
	}
	return ciphertext; 
}

unsigned char*
decode(size_t *ciphertext, int file_size, size_t n, size_t e){
	
	unsigned char* plaintext; 
	plaintext = (unsigned char*)malloc(file_size*sizeof(char));
	size_t tmp; 
	for(int i=0; i<file_size; i++){
		tmp = mod_pow(ciphertext[i], e, n);
		plaintext[i] = (unsigned char)mod_pow(ciphertext[i], e, n); 
	}
	return plaintext; 
}

/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;
	size_t* primes_pool;
	size_t pool_size;
	/* TODO */

	primes_pool = sieve_of_eratosthenes(30, &pool_size);
	choose_from_pool(primes_pool, pool_size, &p, &q);
	n = p*q; 
	fi_n = (p-1)*(q-1);
	e = choose_e(fi_n, primes_pool, pool_size);
	d = mod_inverse(e, fi_n);
	printf("public key : %ld %ld\n", n, d);
	printf("private key : %ld %ld\n", n, e);
	write_key(n, d, "public.txt");
	write_key(n, e, "private.txt");
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{
	unsigned char *plaintext, *key;
	size_t n, d;  
	size_t* ciphertext;   
	int file_size, key_size; 

	// Read file. 
	plaintext = read_file(input_file, &file_size);
	if (plaintext == 0){
		printf("Could not read file.\n");
		exit(0);
	}

	// Read key file.
	key = read_file(key_file, &key_size);
	if (key == 0){
		printf("Could not read file.\n");
		exit(0);
	}

	//Split key file to n and d. 
	memcpy(&n, key, sizeof(size_t));
	memcpy(&d, key+sizeof(size_t), sizeof(size_t));
	printf("public key : %ld %ld\n", n, d); //For testing.

	//Encrypt file. 
	ciphertext = (size_t*)malloc(file_size*sizeof(size_t));
	ciphertext = encode(plaintext, file_size, n, d);

	//write file. 
	write_file(ciphertext, output_file, file_size);
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

	unsigned char *plaintext, *file ,*key;
	size_t *ciphertext;   
	size_t n, e;  
	int file_size, key_size; 

	// Read file. 
	file = read_file(input_file, &file_size);
	if (file == 0){
		printf("Could not read file.\n");
		exit(0);
	}

	//Transform to size_t
	ciphertext = (size_t*)malloc(file_size);
	memcpy(ciphertext, file, file_size/sizeof(size_t));
	//transform_to_size_t(&file)

	// Read key file.
	key = read_file(key_file, &key_size);
	if (key == 0){
		printf("Could not read file.\n");
		exit(0);
	}

	//Split key file to n and e. 
	memcpy(&n, key, sizeof(size_t));
	memcpy(&e, key+sizeof(size_t), sizeof(size_t));
	printf("private key : %ld %ld\n", n, e); //For testing.

	//Decrypt file. 
	plaintext = (unsigned char*)malloc((file_size/sizeof(size_t))*sizeof(unsigned char));
	plaintext = decode(ciphertext, file_size/sizeof(size_t), n, e);

	//write file. 
	write_plaintext(plaintext, output_file, file_size/sizeof(size_t));
	
}
