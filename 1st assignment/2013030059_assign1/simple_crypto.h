
/*
	This file contains the declarations of the encryption-related
	functions defined in "encryption.c". Full descriptions of the
	functions are included above each function definition in
	"simple_crypto.c".
*/

#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPO_H
#define BUFFER_SIZE 2048

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

void otp(char s[BUFFER_SIZE]);
void caesar(char t[BUFFER_SIZE], int shift);
void vigenere(char msg[BUFFER_SIZE], char Vkey[BUFFER_SIZE]);
int main();



#endif	
