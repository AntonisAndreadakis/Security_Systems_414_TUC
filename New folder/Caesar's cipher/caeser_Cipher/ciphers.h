
/****************************************** ^ - ^  **************************************************/

/*A header file containing function prototypes for each function in ciphers.c as well
 *as any macro-defined constants. Should be protected from being included multiple times.
 *
 *Student Name:   Shiyu Wang
 *Student number: 250890597
 *
 **/

/****************************************** ^ - ^ **************************************************/

#ifndef CIPHERS_H
#define CIPHERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LIMIT 60

typedef char* plaintext;
typedef char* ciphertext;
typedef int key;


int find_Length(char* string);
char* capitalize(char* string);
char * caesar_encrypt(char *plaintext, int key);
char * caesar_decrypt(char *ciphertext, int key);
char * vigen_encrypt(char *plaintext, char *key);
char * vigen_decrypt(char *ciphertext, char *key);
void freq_analysis(char *ciphertext, double letters[26]);


#endif




