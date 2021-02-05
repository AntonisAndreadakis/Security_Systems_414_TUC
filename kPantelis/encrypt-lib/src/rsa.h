#ifndef _RSA_H
#define _RSA_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>

#define RSA_SIEVE_LIMIT 255
#define BASE_SIZ sizeof(size_t)

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *sieve_of_eratosthenes(int, int *);

/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int gcd(int , int);


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t choose_e(size_t fi_n, size_t *primePool, int poolSize);


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t mod_inverse(size_t, size_t);

/*
 * Calculates the modular exponentation b^exp mod m.
 *
 * arg0: base
 * arg1: exponent
 * arg2: modulo reductant.
 *
 * ret: modular exponentiation
 */

size_t mod_expo(size_t b, size_t exp, size_t m);


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(void);


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_encrypt(char *, char *, char *);


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void rsa_decrypt(char *, char *, char *);



size_t *encrypt(unsigned char *plaintext, unsigned long len, size_t n, size_t d);
unsigned char *decrypt(size_t *cipher, unsigned long len, size_t n, size_t e);




#endif /* _RSA_H */
