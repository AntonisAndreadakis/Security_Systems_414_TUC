/*	This file contains the implementation code for the encryption-related
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

