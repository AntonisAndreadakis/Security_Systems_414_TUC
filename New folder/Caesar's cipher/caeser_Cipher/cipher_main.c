/****************************************** ^ - ^  **************************************************/

/**This program contains the main function to ask for uesr input and test funtions implemented in ciphers.c
 *
 *
 *Student Name:   Shiyu Wang
 *Student number: 250890597
 *
 **/

/****************************************** ^ - ^ **************************************************/


#include <stdio.h>
#include "ciphers.h"
#include <stdlib.h>
#include <string.h>


int main() {
    //declare the array used to read the user input string
    char string[MAX_LIMIT];

    //declare the array used to read the user input string
    char skey[MAX_LIMIT];

    //delcare a pointers for the string and key and other relevant variables
    char *plaintext;
    int option, key1;
    char* key2;

    //initialize an array with 26 elements which be used in the freq_analysis() fucntion
    double letters[26] = {0};

    //ask for user input text
    printf("Input Plaintext:\n");

    //read the user input using fgets
    if(fgets(string, MAX_LIMIT, stdin) == NULL){
        
	//outputs error message and exit if an error occurs
	printf("Error: Invalid Input!");
        exit(2);

    }
  
    //assign the pointer to points to the string
    plaintext = string;

    printf("\n");

    //prints options and ask for user input
    printf("Available Ciphers:\n 1) Caesar; \n 2) Vigenere;\n");
    printf("\nSelect Cipher: \t");


    //scan the option and print error message is if failed to scan and exit
    if(scanf("%d", &option) != 1){
        printf("Error: Invalid Input!\n");
        exit(2);
    }

    //clear input buffer
    while ((getchar()) != '\n');

    //if request is Caesar
    if(option == 1) {
        printf("\n");
	
	//ask for a number as key
        printf("Input Key as number: \t");

	//if failed to scan, prints error message and exit
        if (scanf("%d", &key1) != 1) {
            printf("Error: Invalid Input!\n");
            exit(2);
        }

	//display plaintext
        printf("\n");
        printf("Plaintext:\n");
        puts(plaintext);

	//call the function to encrypt the text and display the ciphertext
        printf("Ciphertext:\n");
        char *result = caesar_encrypt(plaintext, key1);
        puts(result);


	//call the function to decrypt the ciphertext and display the plaintext
        printf("Decrypted Plaintext:\n");
        char *plain = caesar_decrypt(result, key1);
        puts(plain);

	//call the function freq_analysis() and display the frequency table
        freq_analysis(result, letters);
	
	//free the allocated memory
    	free(result);
        free(plain);

	}
 
    //if the request is Vigenere cipher
    else if(option == 2) {

	//first ask for user input for the plaintext
        printf("\n");
	
	//then ask for the key as a string
        printf("Input Key as string: \t");

	//read the key using fgets, if not reading properly, print error and exit
        if(fgets(skey, MAX_LIMIT, stdin) == NULL){
            printf("Error: Invalid Input!");
            exit(2);

        }

	//make the pointer key2 point to the key
        key2 = skey;
	
	//make another pointer skey2 point to the key
	char* skey2 = key2;

	//loop through the key to make sure the input is valid
	while(*key2 != '\n'){
		
	    //if the element is out of the range for alphabetas, prints out error and exit
            if(*key2 < 65 || *key2 > 122){
                printf("Bad Key! Invalid char!\n");
                exit(2);
            }
		
	    //when it's between capitals and lowercase letter, therefore not alphabeta, prints out error and exit
            else if(*key2> 90 && *key2 < 97){
                printf("Bad Key! Invalid char!\n");
                exit(2);
            }

	    //move pointer by 1
	    key2++;
        }

	//display the untouched plaintext
        printf("\n");
        printf("Plaintext:\n");
        puts(plaintext);

	//call the encryption function and display the return ciphertext
        printf("Ciphertext:\n");
        char* ven_encrpt = vigen_encrypt(plaintext, skey2);
        puts(ven_encrpt);

	//call the decryption function and display the return deciphered text
        printf("Decrypted Plaintext:\n");
        char* ven_decrypt = vigen_decrypt(ven_encrpt, skey2);
        puts(ven_decrypt);

	//call the frequency function and display the frequency table
        freq_analysis(ven_encrpt, letters);

	//free the allocated memory
	free(ven_encrpt);
        free(ven_decrypt);
    }
   
    //if any cipher option other than 1 and 2 are given, print out error and exit
    else{
        printf("\nError: Bad selection! \n");
	exit(2);

    }




    return 0;
}
