## Description:

Purpose of this assignment is to generate an asymmetric encryption tool, written in C.
It provides RSA key-pair generation, encryption and decryption.

## Modes:

`key derivation`
	-Generate a pool of primes using the Sieve of Eratosthenes. The sieve's limit is defined in rsa.h file.
	-Pick 2 random primes from the pool. Call them p and q.
	-Compute n = p * q.
	-Calculate fi(n) = (p-1)*(q-1). This is Euler's totient function.
	-Implement Greatest Common Denominator function gcd().
	-Choose a prime number e where (e%fi(n))!=0 AND gcd(e,fi(n))==1.
	-Implement function for modular inverse.
	-Choose d = mod(e,fi(n))
	-Public key consists of n and d.
	-Private key consists of n and e.

`encryption`
	-Using one of the keys generated in above step, this part encrypts
	data of an input file.
	-Store the ciphertext to an output file.
	-The encrypted message is saved.

`decryption`
	-Read the ciphertext from an input file.
	-Using the appropriate key of the two generated in first step, depending
	on which one was used for the ciphertext encryption. Keys are generated
	as described in first step and decrypts data of the input file.
	-The decrypted plaintext is saved to an output file.

`debug`
	I also provide a debug mode, simply adding '1' at the end of the command, to enable debuging.

## Example:

example:	./assign_3 -i plaintext.txt -o cipher.txt -k public.key -e(for enable) 1(to enable debug mode)
	

