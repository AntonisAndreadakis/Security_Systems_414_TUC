 

#ifndef crypto_h
#define crypto_h

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <fcntl.h> 
#include <unistd.h>


// A kinda important contract with my compiler.
typedef u_int8_t uint8_t;


/*
	Needed constants for working with buffers, streams etc.

*/
#ifndef BUF_SIZE
#define BUF_SIZE 512
#endif 

#ifndef RANDOM_DEV
#define RANDOM_DEV "/dev/urandom"
#endif


#define POOL_SIZE 62 //actual size of the character pool [26 capitals, 26 small, 10 numbers [0-9]]
#define ALPHA_POOL_SIZE 26

FILE *randGen;

//useful adjacent matrices.

char charPool[POOL_SIZE];
char caps[ALPHA_POOL_SIZE];
char vPool[ALPHA_POOL_SIZE][ALPHA_POOL_SIZE];


/*
	UTILITY FUNCTION PROTOTYPES
*/

/*
	Initializes a poll of valid characters by defining a set of 52 letters and 9 numbers.
*/
void poolInit();

/*
	Symmetric with <poolInit> but in 2-d space.
*/
void vPoolInit();

/*
	** Utility functions for handling operations in the char pool (set). **
	
*/


int getPoolIndex(char c);
int getCapsIndex(char c);
char getRandomDigit();
char *getRandomKey(int siz);
void printHex(char *key);
char *extendKey(char *orig, char *key);

/*
	** Input handlers **

*/


/*
	Input formatter in the valid form [0-9 A-Z a-z].
	Receives a string with possibly invalid characters ['$', '@', '\tab', etc..] and purifies it to the form [0-9A-Za-z].

	Args:	< *inp >:	pointer to original string.
	Returns: NULL if inp is NULL, the purified string in any other case.

*/
char *formatInput(char *inp);

/*
	Reads any given input (from stdin) dynamically by resizing the input buffer when needed.
	This is done exclusivelly to intercept any attempt for buffer overflow attacks.
	Args:		None.
	Returns:	The input collected from stdin via a pointer.
	Warning:	Input might contain illegal charactes other than A-Z, a-z, 0-9..
	Note:		You might want to use "char *formatInput()" on the result to sanitize it!

*/

char *readInput();



/*
	
	** Crypto Functions **

*/

char *encryptOTP(char *inp,  char *key);
char *decryptOTP(char *inp, char *key);
char *encryptCeasar(char *inp, int k);
char *decryptCeasar(char *inp, int k);
char *encryptVigenere(char *inp, char *key);
char *decryptVigenere(char *inp, char *key);


#endif