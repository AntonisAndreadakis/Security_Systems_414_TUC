#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

//helper functions
char* randomGenerator(char plaintext[]);

/*****************************************************
** Produces random ASCII characters using /urandom.	 *
******************************************************/

char* nonBufferedOvfInput();

/*****************************************************
** The program is not vulnerable in buffer ovferflow *
** attacks.											 *	
******************************************************/
char* nonBufferedOvfInputUpper();
/*****************************************************
** The program is not vulnerable in buffer ovferflow *
** attacks. Only for Vigenere cipher input.			 *	
******************************************************/

//assignment functions
void otp_encrypt_decrypt(char inpString[],char* key);

/*****************************************************
** One Time pad encryption/decryption algorithm.     *
** 													 *
** Input: The plaintext for encryption or the cipher *
** text for decryption. Also the key.				 *				
** 													 *
** Output: The encrypted cipher text or the original *
** plaintext.										 *
******************************************************/

void ceasars_cipher(char inpString[], int key);

/*****************************************************
** Caesars cipher encrypt/decrypt algorithm.		 *
** 													 *
** Input: The plaintext for encryption or the cipher *
** text for decryption. Also the key. 				 *												 
** 													 *
** Output: The encrypted cipher text or the original *
** plaintext.										 *
******************************************************/

void vigenere(char inpString[], char* key);

/*****************************************************
** Vigenere encrypt/decrypt algorithm.				 *
** 													 *
** Input: The plaintext for encryption or the cipher *
** text for decryption. Also the key. 				 *												 
** 													 *
** Output: The encrypted cipher text or the original *
** plaintext.										 *
******************************************************/


#endif