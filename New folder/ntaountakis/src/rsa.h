#ifndef _RSA_H
#define _RSA_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>

# define RSA_SIEVE_LIMIT 255
# define MAXBUFLEN 100000

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
sieve_of_eratosthenes(int, int *);
void choose_from_pool(size_t* pool, int pool_size, size_t *num1, size_t *num2);
void write_key(size_t num1, size_t num2 ,char* key_type);
int extended_eucl(size_t a, size_t b,size_t *x, size_t *y);
unsigned char* read_file(char* file_name, int *file_size);
size_t *
encode(unsigned char *plaintext, int plaintext_size, size_t n, size_t d);
unsigned char *
decode(size_t *ciphertext, int file_size, size_t n, size_t e);
size_t mod_pow(size_t base, size_t expn, size_t md);

/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int , int);


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t, size_t*, int);


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t, size_t);


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void);


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *, char *, char *);


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *, char *, char *);

#endif /* _RSA_H */
