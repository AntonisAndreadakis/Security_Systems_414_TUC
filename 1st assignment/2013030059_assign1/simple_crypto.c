#if 0 /* Original submission retained for review. */
	This file contains the implementation code for the encryption-related
	functions declared in "simple_crypto.h".       */

     #include <stdio.h>   
     #include <stdlib.h>  
     #include <stdint.h> 
     #include <string.h>
     #include <ctype.h>
     #include <unistd.h>
     #include <fcntl.h>
     #include "simple_crypto.h"
     
     //Create a variable to be used for all functions which serves as the max input size:
     #define BUFFER_SIZE 2048
    
    
/* ########## OTP algorithm: ########### */
     void otp(char s[BUFFER_SIZE]) {        
        //Initialize variables:
        int i, N;
        char b[BUFFER_SIZE];
        char key[BUFFER_SIZE];
                                                 
        //store in variable:
        strcpy(b, s);                
        printf("\t[OTP] input:		%s\n", b);
        N = strlen(b);
        // check input:
       for (i = 0; i<N; i++){
          int asciVal;
          asciVal = b[i];
          if ((asciVal<48 || asciVal>57) && (asciVal<65 || asciVal>90) && (asciVal<97 || asciVal>122)){
            exit(0);
            }
        }

        for (i = 0; i<N; i++) {
        // generate random key of the same length as the input:
          key[i] = open("/dev/urandom", O_RDONLY);
          }
        for (i = 0; i<N; i++) {
        // generate cipher by XORing each bit of message with each bit of key:
          b[i] ^= key[i];          
           }
        printf("\t[OTP] encrypted:	%s\n", b);
        // decrypt cipher by XORing each bit of cipher with each bit of the key:
        for (i = 0; i<N; i++) {
          b[i] ^= key[i];
          }
        printf("\t[OTP] decrypted:	%s\n", b);
       }         



/* ########## Caesar's cipher algorithm: ########### */
              void caesar(char t[BUFFER_SIZE], int shift){
                    int i,N;
                    char e;                                                                                                   
                    printf("\t[Caesar's] input:	%s\n", t);
                    printf("\t[Caesar's] key:		%d\n", shift);
                    N = strlen(t);
                    // check input:
                    for (i = 0; i<N; i++){
                      int asciVal;
                      asciVal = t[i];
                      if ((asciVal<48 || asciVal>57) && (asciVal<65 || asciVal>90) && (asciVal<97 || asciVal>122)){
                         exit(0);
                         }
                     }           
                    // encryption:                    
                    for (i = 0; t[i]!='\0'; i++) {
                      e = t[i];
                      // check if input is in range of alpabet for lowercase:
                      if (e >= 'a' && e <= 'z') {
                          e = e + shift;
                          if (e > 'z'){
                             e = e - 'z' + 'a' - 1;
                             }
                          t[i] = e;
                          }
                      // check if input is in range of alpabet for uppercase:
                      else if (e >= 'A' && e <= 'Z') {
                         e = e + shift;
                         if (e > 'Z') {
                            e = e - 'Z' + 'A' - 1;
                             }
                           t[i] = e;
                          }
                       // check if input is in range of alpabet for numbers:
                       else if (e >= '0' && e <= '9') {
                          e = e + shift;
                          if (e > '9') {
                            e = e - '9' + '0' - 1;
                              }
                           t[i] = e;
                         }
                      }                   
                      printf("\t[Caesar's] encrypted:	%s\n", t);

                      // reverse method to decrypt
                      // decryption:
                      for (i = 0; t[i]!='\0'; i++) {
                        e = t[i];
                        // check if input is in range of alpabet for lowercase:
                        if (e >= 'a' && e <= 'z') {
                          e = e - shift;
                          if (e > 'z'){
                             e = e + 'z' - 'a' + 1;
                             }
                          t[i] = e;
                          }
                        // check if input is in range of alpabet for uppercase:
                        else if (e >= 'A' && e <= 'Z') {
                           e = e - shift;
                           if (e > 'Z') {
                              e = e + 'Z' - 'A' + 1;
                               }
                            t[i] = e;
                           }
                          // check if input is in range of alpabet for numbers:
                          else if (e >= '0' && e <= '9') {
                          e = e - shift;
                          if (e > '9') {
                            e = e + '9' - '0' + 1;
                              }
                           t[i] = e;
                           }
                         }
                         printf("\t[Caesar's] decrypted:	%s\n", t);
                       }


/* ########## Vigenere's cipher algorithm: ########### */
                     void vigenere(char msg[BUFFER_SIZE], char Vkey[BUFFER_SIZE]){                                
                        
                        printf("\t[Vigenere] input:	%s \n", msg);
                        printf("\t[Vigenere] key:		%s \n", Vkey);
                     
                        char enc[strlen(msg)], de[strlen(msg)];
                        int i, position = 0;
                        int key_length = strlen(Vkey);
                        int N = strlen(msg);

                        // check input:
                        for (i = 0; i<N; i++){
                           int asciVal;
                           asciVal = msg[i];
                           if ((asciVal<65 || asciVal>90) && (asciVal<97 || asciVal>122)){
                              exit(0);
                             }
                         }
                           for (i = 0; i<key_length; i++){
                           int asciVal;
                           asciVal = Vkey[i];
                           if ((asciVal<65 || asciVal>90) && (asciVal<97 || asciVal>122)){
                              exit(0);
                             }
                         }

                        // check if input is lowercase:
                        for (i = 0; msg[i]!='\0'; i++) {
                          if (msg[i] >= 'a' && msg[i] <= 'z') {
                          // convert to upper:
                            msg[i] = msg[i] - 32;
                            //break;
                            }
                          }
                         // check if key is lowercase:
                         for (i = 0; msg[i]!='\0'; i++) {                         
                           if (Vkey[i] >= 'a' && Vkey[i] <= 'z') {
                            // convert to upper:
                            Vkey[i] = Vkey[i] - 32;
                             //break;
                            }
                          }
                       // encryption:                       
                       for (i = 0; msg[i]!='\0'; i++){
                          enc[i] = ' '; // clear cruft before populating
                          if (msg[i] >= 'A' && msg[i] <= 'Z'){
                             enc[i] = ((msg[i] + Vkey[position]) %26) + 'A';
                             position++;
                             if (position == key_length){
                                position = 0;
                                }
                            }
                        }
                       enc[i] = '\0';
                       printf("\t[Vigenere] encryption:	%s\n", enc);    

                       for (i = 0; msg[i]!='\0'; i++) {
                         // check if input is lowercase:
                         if (msg[i] >= 'a' && msg[i] <= 'z') {
                         // convert to upper:
                            msg[i] = msg[i] - 32;
                            }
                          }
                       // reverse method to decrypt
                       // decryption:
                       for (i = 0; msg[i]!='\0'; i++){
                          //de[i] = ' '; // clear cruft before populating
                          if (msg[i] >= 'A' && msg[i] <= 'Z'){
                             de[i] = ((enc[i] - Vkey[position] + 26) % 26)+'A';
                             position++;
                             if (position == key_length){
                                position = 0;
                                }
                            }
                        }
                       de[i] = '\0';
                       printf("\t[Vigenere] decryption:	%s\n", de);
                      }
#endif

#include "simple_crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int crypto_is_alnum62(const char *text)
{
	const unsigned char *cursor = (const unsigned char *)text;

	if (cursor == NULL || *cursor == '\0')
		return 0;
	while (*cursor != '\0') {
		if (strchr(SIMPLE_CRYPTO_ALPHABET, (int)*cursor) == NULL)
			return 0;
		++cursor;
	}
	return 1;
}

int otp_generate_key(unsigned char *key, size_t length)
{
	size_t offset = 0;
	int descriptor;

	if (key == NULL && length != 0)
		return -1;
	descriptor = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
	if (descriptor == -1)
		return -1;
	while (offset < length) {
		ssize_t count = read(descriptor, key + offset, length - offset);
		if (count > 0) {
			offset += (size_t)count;
			continue;
		}
		if (count < 0 && errno == EINTR)
			continue;
		(void)close(descriptor);
		return -1;
	}
	return close(descriptor) == 0 ? 0 : -1;
}

void otp_xor(const unsigned char *input, const unsigned char *key,
             unsigned char *output, size_t length)
{
	size_t i;

	for (i = 0; i < length; ++i)
		output[i] = input[i] ^ key[i];
}

static int caesar_transform(const char *input, int shift, int decrypt,
                            char *output, size_t capacity)
{
	size_t length;
	size_t i;
	int normalized;

	if (!crypto_is_alnum62(input) || output == NULL || shift < 0)
		return -1;
	length = strlen(input);
	if (capacity <= length)
		return -1;
	normalized = shift % SIMPLE_CRYPTO_ALPHABET_SIZE;
	if (decrypt && normalized != 0)
		normalized = SIMPLE_CRYPTO_ALPHABET_SIZE - normalized;
	for (i = 0; i < length; ++i) {
		const char *position = strchr(SIMPLE_CRYPTO_ALPHABET, (unsigned char)input[i]);
		size_t index = (size_t)(position - SIMPLE_CRYPTO_ALPHABET);
		output[i] = SIMPLE_CRYPTO_ALPHABET[(index + (size_t)normalized) %
		                                      SIMPLE_CRYPTO_ALPHABET_SIZE];
	}
	output[length] = '\0';
	return 0;
}

int caesar_encrypt(const char *input, int shift, char *output, size_t capacity)
{
	return caesar_transform(input, shift, 0, output, capacity);
}

int caesar_decrypt(const char *input, int shift, char *output, size_t capacity)
{
	return caesar_transform(input, shift, 1, output, capacity);
}

static int is_uppercase_text(const char *text)
{
	const unsigned char *cursor = (const unsigned char *)text;

	if (cursor == NULL || *cursor == '\0')
		return 0;
	while (*cursor != '\0') {
		if (*cursor < 'A' || *cursor > 'Z')
			return 0;
		++cursor;
	}
	return 1;
}

static int vigenere_transform(const char *input, const char *key, int decrypt,
                              char *output, size_t capacity)
{
	size_t input_length;
	size_t key_length;
	size_t i;

	if (!is_uppercase_text(input) || !is_uppercase_text(key) || output == NULL)
		return -1;
	input_length = strlen(input);
	key_length = strlen(key);
	if (capacity <= input_length)
		return -1;
	for (i = 0; i < input_length; ++i) {
		int value = input[i] - 'A';
		int key_value = key[i % key_length] - 'A';
		if (decrypt)
			value = (value - key_value + 26) % 26;
		else
			value = (value + key_value) % 26;
		output[i] = (char)('A' + value);
	}
	output[input_length] = '\0';
	return 0;
}

int vigenere_encrypt(const char *input, const char *key,
                     char *output, size_t capacity)
{
	return vigenere_transform(input, key, 0, output, capacity);
}

int vigenere_decrypt(const char *input, const char *key,
                     char *output, size_t capacity)
{
	return vigenere_transform(input, key, 1, output, capacity);
}
