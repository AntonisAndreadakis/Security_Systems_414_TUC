#include <stdio.h>
#include "ciphers.h"
#include <stdlib.h>
#include <string.h>

/****************************************** ^ - ^  **************************************************/

/**This program contains the code for the encryption and decryption functions for each cipher
 *also two helper functions find_Length() and capitalize() 
 *
 *Student Name:   Shiyu Wang
 *Student number: 250890597
 *
 **/

/****************************************** ^ - ^ **************************************************/

//helper function to find the length of the string given
int find_Length(char* string){

    //initialize string length to 0
    int i=0;

    //use while loop to count each element and update the count
    while(*string != '\0') {
        i++;
        string++;
    }

    //return the string length including the null terminator
    return i;
}

//another helper function to convert lowercase to capital letters
char* capitalize(char* string){

    //first find the length of the string
    int len = find_Length(string);

    //dynamically allocate the memory for the new capitalized string
    char* capital = (char*) calloc(len, len*sizeof(char));
    
    //print out error if error has occurred while allocating memory and exit
    if(capital == NULL){
        printf("Error allocating memory!");
        exit(1);
    }
  
    //assign a new pointer to point at the same memory location
    char* new = capital;

    //convert all lowercase letters to capitals
    while(*string != '\0'){

	//if lowercase, then convert to capitals
        if(*string >= 'a' && *string <= 'z') {

            *capital =  *string - 32;

            capital++;
        }

	//else just copy the same string to the new memory location
        else{

            *capital = *string;
            capital++;

        }

        string++;
    }

    //return the pointer that points to the start of the string
    return new;

}
/************************************************************************************/

char * caesar_encrypt(char *plaintext, int key){

    //first to make the plaintext all capitals
    char* new = capitalize(plaintext);

    //assign a new pointer to point at the start of the string
    char* result = new;

     //generate new key if shift more than 26
    if(abs(key) > 26) {
	
	//if positve, use module to get the shift
        if (key > 0)
            key = key % 26;

	//if negative, convert it to positve and back to negative
        else if(key < 0){
            key = key * (-1);
            key = key % 26;
            key = key * (-1);

        }
    }

    //make an array of 26 alphabetas 
    char alphabeta[26] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
   
    //declare variable used for loop
    int i,index;

    //loop through the capitalized plaintext until reach the end
    while(*new != '\0'){

	//loop through the alphabeta array 
        for(i = 0; i < 26; i++){

	    //if found the same letter in alphabeta, start shift 
            if(*new == alphabeta[i]){
		
		//if the shift is towards right
                if(key>0) {	

		    //if the shift is greater than the rest of the string
                    if (key >= (26 - i)) {
			
			//circles back to the start and shift of the key minus the rest of the string length
                        index = key - (26 - i);

			//update the char after the shift
                        *new = alphabeta[index];
			
		    //if the shift is not greater than the rest of the string
                    } else
			
			//just shift right the key length 
                        *new = alphabeta[i + key];
                }
		
		//if the shift is towards left
                else if(key < 0){

		    //if the shift is greater than the num of elements travelled so far
                    if(i < abs(key)) {

			//the shift is done by adding the whole length of the alphabeta array and 
			//shift left the key + 1 units 
                        *new = alphabeta[i + 26 + key];
                    }
		    //if the shift is no greater than the num of the elements travelled so far
                    else {
	
			//just shift left
                        *new = alphabeta[i + key];
                    }
                }
		//if the shift is 0, do nothing and return
                else{
                    return plaintext;

                }
		
		//no more than one shift per element
                break;
            }
        }

	//update pointer
        new++;
    }



    return result;


}
/************************************************************************************/


char * caesar_decrypt(char *ciphertext, int key){

 //generate new key if shift more than 26
    if(abs(key) > 26) {
        if (key > 0)
            key = key % 26;

        else{
            key = key * (-1);
            key = key % 26;
            key = key * (-1);

        }
    }	
    //find the length of the string
    int len = find_Length(ciphertext);

    //allocate memory on heap for the decrypted text
    char* plaintext = (char*) calloc(len,len*sizeof(char));

    //print error message if an error has occured and exit
    if(plaintext == NULL){
        printf("Error allocating memory!");
        exit(1);
    }

    //copy the ciphertext to plaintext
    strcpy(plaintext, ciphertext);

    //assign a new pointer to point at the working string
    char* plain = plaintext;

    int i,index;

    char alphabeta[26] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    //loop through the working string to decipher
    while(*plaintext != '\0'){

	//loop through the alphabeta array
        for(i = 0; i < 26; i++){
		
	    //if found an alphabeta the same as the string element	
            if(*plaintext == alphabeta[i]){

		//if the shift is towards left
                if(key > 0) {
		
		    //if the key is greater than what's travelled so far
                    if (i < key) {
			
			//calculate the index
                        index = 26 - (key - i );
			
			//update the new char
                        *plaintext = alphabeta[index];
		
		    //if the shift does not exceeds the boundary of the array
                    } else

			//just shift left
                        *plaintext = alphabeta[i - key];
                }

		//if the shift is towards right
                else if(key < 0){

		    //if the shift is greater than what's left to travel
                    if(abs(key) >= (26 - i)) {

			//calculate the index
                        *plaintext = alphabeta[abs(key)-(26-i)];
                    }
		    // if the shift is no greater than what's left to teavel
                    else {
			//just shift right
                        *plaintext = alphabeta[i + abs(key)];
                    }
                }

		//if shift is 0, do nothing and return the plaintext
                else{
                    return ciphertext;

                }

                break;
            }
        }
        plaintext++;
    }


    return plain;
}

/************************************************************************************/




char * vigen_encrypt(char *plaintext, char *key){

    //standard finding the length of the text
    int len = find_Length(plaintext);

    //find the length of the key
    int lenKey = find_Length(key);

    //store the return of the capitalized text in a pointer
    char* new = capitalize(plaintext);
    //also assign another pointer to point at the same location
    char* result = new;

    //store the	return of the capitalized key in a pointer
    char* cap_Key = capitalize(key);

    //dynamically allocate the memory for the new key 
    char* newKey = (char*) calloc(len, len*sizeof(char));
    int i,j;

    //generate new key with the same length as the plaintext by padding
    for (i = j = 0; j < len-1; j++) {
	
	//skip the null terminator and circle back to the beginning of the key
        if(i%lenKey == lenKey-1)
            i++;
	
	//keep padding the key 
        newKey[j] = cap_Key[i%lenKey];

        i++;
    }



    char alphabeta[26] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    
    //declare variable used for the shift
    int shift1, shift2;

    //loop through the working string
    for(i = 0; i< len; i++){

	//if the element is a letter
        if(new[i] >= 65 && new[i] <= 90){
		
	    //we loop through the alphabeta array
            for(j = 0; j < 26; j++){

		//if found the same letter as the string element, record the shift1
                if(new[i] == alphabeta[j]){

                    shift1 = j;

                }

		//if found the same letter as the key element, record the shift2
                if(newKey[i] == alphabeta[j] ){
                    shift2 = j;


                }

            }
	    //update the letter in the working string
            new[i] = alphabeta[(shift1+shift2)%26];
        }
    }

    //free the memory allocated for generating new key and return the result
    free(newKey);

    return result;
}
/************************************************************************************/



char * vigen_decrypt(char *ciphertext, char *key){

    //find length of the string and key
    int len = find_Length(ciphertext);
    int lenKey = find_Length(key);

    //call the capitlaize function for the string
    char* new = capitalize(ciphertext);
    char* result = new;

    //call the capitlaize function for the key
    char* cap_Key = capitalize(key);

    //dynamically allocate the memory for new key
    char* newKey = (char*) calloc(len, len*sizeof(char));
    int i,j;

    //generate new key with the same length as the plaintext by padding
    for (i = j = 0; j < len-1; j++) {
	
	//if reach the null terminator, skip it and circle back to the start
        if(i%lenKey == lenKey-1)
            i++;

	//keep padding
        newKey[j] = cap_Key[i%lenKey];

        i++;
    }


    //create an arrat storing all the alphabetas
    char alphabeta[26] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    //decalre variables used to calculate the shift
    int shift, shift1, shift2;

    //loop through the working string
    for(i = 0; i< len; i++){

	//if the element is a letter
        if(new[i] >= 65 && new[i] <= 90){
	   
           //loop through the alphabeta array 
           for(j = 0; j < 26; j++){
		//if same letter is found for the string element, record it as shift 1 
                if(new[i] == alphabeta[j]){

                    shift1 = j;

                }

		//if same letter is found for the key element, record it as shift 2
                if(newKey[i] == alphabeta[j] ){
                    shift2 = j;


                }

            }
	    //calculate the shift
            shift = shift1 - shift2;
	   
  	    // if the shift is towards right
            if(shift < 0) {
		//do the calculation
                shift = 25 + shift +1;

                new[i] = alphabeta[shift];
            }
	    //else just shift
            else
                new[i] = alphabeta[shift];
        }
    }

    //free the memory
    free(newKey);
    return result;

}

/************************************************************************************/

void freq_analysis(char *ciphertext, double letters[26]){

    //first make a new pointer which points to the array of 26 alphabetas
    double* pointer = letters;
    double* new = pointer;
     
    //declare variables used for later
    int i, shift;

    //initalize the variable to keep track of the number of letters in the ciphertext
    int len = 0;


    //set all values in the array to be null;
    for(i=0; i< 26; i++){

        *pointer = 0;
	
        pointer++;
    }


    //loop through the text
    while(*ciphertext != '\0'){
	
	//if the element is a lowercase letter
        if(*ciphertext >= 'a' && *ciphertext <= 'z'){

            //increment the number of the letters by 1
	    len++;

	    //calcaulate the index in the array
            shift = *ciphertext - 'a';

	    //move the pointer to the location
            new += shift;

	    //update the array element by 1
            (*new)++;
		
	    //move the pointer back to the start
            new -= shift;
        }

	//if the element is a capital letter. do the same thing, just the calculate of index differs
        else if(*ciphertext >= 'A' && *ciphertext <= 'Z'){
            len++;
            shift = *ciphertext - 'A';
            new += shift;
            (*new)++;
            new -= shift;

        }
	//move the pointer by 1
        ciphertext++;

    }

    
    printf("\nFrequency Analysis: \n");

    //prinf the 26 letters with specific format
    for(i = 'A'; i<= 'Z'; i++){
        printf("%5c ",i);
    }
    printf("\n");

    //calculate the 26 frequencies and output with specific format
    for(i = 0; i< 26; i++){
	//the frequency is calucalted by dividing the number of letters in the ciphertext and times 100%
        *new = *new/len*100;
        printf("%5.1f ",*new);
        new++;
    }
   printf("\n");
}

