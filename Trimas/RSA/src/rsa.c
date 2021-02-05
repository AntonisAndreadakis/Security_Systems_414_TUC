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

size_t* sieve_of_eratosthenes(int limit, int *primes_sz)
{
	// size_t* primes;
 	size_t *prime = malloc((limit+1)*sizeof(size_t));
	size_t i,j,k=2;
	int tmp;
	/* TODO */	

	for(i = 2; i <= limit; i ++)
		prime[i] = i;

	for(i = 2; i*i <= limit; i ++)
	{
		for(j = i*i; j <= limit; j += i)
			prime[j] = 0;
	}	
		
	for (i = 0; i < limit; i++)
	{
		if(prime[i]  != 0)
		tmp++; //use as a counter
	}

	size_t *primes = malloc(tmp*sizeof(size_t));
	tmp = 0;

	for(i = 2; i <= limit; i ++)
	{
		
		if(prime[i] != 0)
		{
			primes[tmp] = prime[i];
			tmp++;
		}
	}

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
int gcd(int a, int b)
{

	/* TODO */
	int tmp;

	while(a != 0)
	{
		tmp = a;
		a = b % a;
		b = tmp;
	}

	return b;

}

// extra function No.1

size_t compute_n(size_t p, size_t q)
{
	return p * q;
}

// extra function No.2

size_t calc_fi_n(size_t p, size_t q)
{
	return (p-1)*(q-1);
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t* fi_n, size_t* n)
{
	size_t e, fi;
	/* TODO */
	srand(time(NULL));
	size_t *prime = sieve_of_eratosthenes(RSA_SIEVE_LIMIT, NULL); //might delete the second arg later

	while(1)
	{
		e = prime[rand()%sizeof(prime)];
		size_t p = prime[rand()%sizeof(prime)];
		size_t q = prime[rand()%sizeof(prime)];

		if(p == 1 || q == 1)
			continue;

		fi = calc_fi_n(p ,q);

		if( 1 < e && e < fi && gcd(e, fi) == 1 && e%fi != 0  )
		{
			*fi_n = fi;
			*n = compute_n(p,q);
			return e;
		}
	}
}

// extra function No.3

size_t gcdExtended(size_t a, size_t b, size_t* x, size_t* y) 
{ 
    // Base Case 
    if (a == 0) 
    { 
        *x = 0; 
        *y = 1; 
        return b; 
    } 
  
    size_t x1, y1; // To store results of recursive call 
    size_t gcd = gcdExtended(b % a, a, &x1, &y1); 
  
    // Update x and y using results of recursive 
    // call 
    *x = y1 - (b / a) * x1; 
    *y = x1; 
  
    return gcd; 
} 
/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t mod_inverse(size_t e, size_t fi) // changed var names from a,b to e,fi respectively
{

	/* TODO */
	size_t x, y, g = gcdExtended(e, fi, &x, &y);

	if(g != 1)
		return -1;

	if ((e*x) % fi == 1)
		return x;
	
	if ((e*y) % fi == 1)
		return y;
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e = choose_e(&fi_n, &n);
	size_t d = mod_inverse(e, fi_n);

	/* TODO */
	char* private_key_fl = "private.key";
	char* public_key_fl = "public.key";
	FILE* fp1, *fp2;

	if ((int)d < 0)
	{
		tmp_d = 0;
		printf("e = %ld\tf(n) = %ld\n",e, fi_n);
		printf("d = %d\tn = %ld\n",tmp_d, n);
	}

	else
	{
		printf("e = %ld\tf(n) = %ld\n",e, fi_n);
		printf("d = %ld\tn = %ld\n",d, n);
	}

	fp2 = fopen(public_key_fl, "wb");

	fwrite(&n, sizeof(size_t), PLAIN_SIZE, fp2);
	fwrite(&d, sizeof(size_t), PLAIN_SIZE, fp2);
	fclose(fp2);

	fp1 = fopen(private_key_fl, "wb");

	fwrite(&n, sizeof(size_t), PLAIN_SIZE, fp1);
	fwrite(&d, sizeof(size_t), PLAIN_SIZE, fp1);
	fclose(fp1);
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */

void rsa_encrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */
	size_t* ciphertext;
	char* plaintext;
	size_t n, e, i = 0;

	FILE* fp = fopen(input_file, "rb");
	FILE* key = fopen(key_file, "rb");

	if(fp == NULL || key == NULL)
	{
		fprintf(stderr, "Error");
		exit(EXIT_FAILURE);
	}

	// from assignment No.2
	fseek(fp, 0, SEEK_END);
	long int numOfBytes = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	plaintext = malloc(numOfBytes);
	ciphertext = malloc(numOfBytes);

	fread(&n, sizeof(size_t), PLAIN_SIZE, key);
   	fread(&e, sizeof(size_t), PLAIN_SIZE, key);

	size_t pl_lgth = fread(plaintext, PLAIN_SIZE, numOfBytes, fp);

	for(; i < pl_lgth; i++)
	{
		ciphertext[i] = modExp(plaintext[i], e, n);
		// printf("%ld\n",ciphertext[i]);
	}

	FILE* output = fopen(output_file, "wb");
	fwrite(ciphertext, CIPHER_SIZE, numOfBytes, output);

	fclose(output);
	fclose(fp);
}

// extra function No.4

unsigned long modExp(unsigned long a, unsigned long b, unsigned long c)
{
	if(a < 0 || b < 0 || c <= 0)
	{
		exit(EXIT_FAILURE);
	}

	a = a % c;

	if(b == 0)
		return 1;

	if(b ==1)
		return a;

	if(b % 2 == 0)
	{
		return(modExp(a*a % c, b / 2, c) % c);
	}

	if(b % 2 == 1)
	{
		return(a * modExp(a, b-1, c) % c);
	}
}
/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */

void rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */
	size_t* ciphertext;
	char* plaintext;
	size_t n, e, i = 0;

	FILE* fp = fopen(input_file, "rb");
	FILE* key = fopen(key_file, "rb");

	if(fp == NULL || key == NULL)
	{
		fprintf(stderr, "Error");
		exit(EXIT_FAILURE);
	}

	// from assignment No.2
	fseek(fp, 0, SEEK_END);
	long int numOfBytes = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	ciphertext = malloc(sizeof(size_t) * numOfBytes);
	
	fread(&n, sizeof(size_t), PLAIN_SIZE, key);
   	fread(&e, sizeof(size_t), PLAIN_SIZE, key);
   	
	size_t cphr_lgth = fread(ciphertext, sizeof(size_t), numOfBytes, fp);
	plaintext = malloc(cphr_lgth);


	for(; i < cphr_lgth; i++)
	{
		plaintext[i] = modExp(ciphertext[i], e, n);
		// printf("%ld\n",ciphertext[i]);
	}

	FILE* output = fopen(output_file, "wb");
	fwrite(plaintext, PLAIN_SIZE, cphr_lgth, output);

	fclose(output);
	fclose(fp);
}
