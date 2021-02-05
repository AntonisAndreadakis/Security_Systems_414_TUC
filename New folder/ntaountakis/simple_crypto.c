#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "simple_crypto.h"




char* oneTimePadEncrypt(char* plaintext, char* key){

    int textSize = strlen(plaintext);
    char *cypherText = (char*) malloc((textSize+1)*sizeof(char));
    
    for (int i=0; i<textSize; i++){
        cypherText[i] = plaintext[i] ^ key[i];
    }

    return cypherText;
}

char* oneTimePadDecrypt(char* cyphertext, char* key){

    int textSize = strlen(cyphertext);
    char *plaintext = (char*) malloc((textSize+1)*sizeof(char));

    for (int i=0; i<strlen(cyphertext); i++){
        plaintext[i] = (char)(cyphertext[i] ^ key[i]);
    }

    return plaintext;
}

char* caesarCipherEncrypt(char* plaintext, int key){
    int textSize = strlen(plaintext);
        /*
        DEC for 0-9 : 48-57
        DEC for A-Z : 65-90 
        DEC for a-z : 97-122

        */

    int asciiTable[62];
    
    for (int i=0; i < 62; i++){
        if (i <= 9)
            asciiTable[i] = 48+i;
        else if (i <= 35)
            asciiTable[i] = 65+i-10;
        else
            asciiTable[i] = 97+i-36;        
    }
    
    
    
    char* cyphertext = (char*)malloc((textSize+1)*sizeof(char));

    for (int i=0; i< textSize; i++){                 
        *(cyphertext+i) = shiftCharacter(plaintext[i], key, asciiTable, UP);  
    }
    return cyphertext;
    
}

char* caesarCipherDecrypt(char* cyphertext, int key){
    int textSize = strlen(cyphertext);
    int asciiTable[62];
    
    for (int i=0; i < 62; i++){
        if (i <= 9)
            asciiTable[i] = 48+i;
        else if (i <= 35)
            asciiTable[i] = 65+i-10;
        else
            asciiTable[i] = 97+i-36;        
    }

    
    char *plaintext = (char*)malloc((textSize+1)*sizeof(char));
    for (int i=0; i< textSize; i++){                 
        *(plaintext+i) =shiftCharacter(cyphertext[i], key, asciiTable, DOWN);  
    }

    return plaintext;
}

char* vigenereCipherEncrypt(char* plaintext, char* key){
    
    char** tabulaRecta = getTabulaRecta();
    int textSize = strlen(plaintext);
    char* newkey = adjustKey(key, textSize);
    char* cyphertext = (char*)malloc((textSize+1)*sizeof(char));

    for (int i=0; i<textSize; i++){
        *(cyphertext+i) = tabulaRecta[(int)newkey[i]-65][(int)plaintext[i]-65];
    }
    return cyphertext; 
}

char* vigenereCipherDecrypt(char* cyphertext, char* key){

    char** tabulaRecta = getTabulaRecta();
    int textSize = strlen(cyphertext);
    char* newkey = adjustKey(key, textSize);

    char* plaintext = (char*)malloc((textSize+1)*sizeof(char));
    for (int i=0; i<textSize; i++){
        for (int j=0; j < 26; j++){
            if ((int)tabulaRecta[(int)newkey[i]-65][j] == (int)cyphertext[i]){ 
                char test = (char)(j+65);
                *(plaintext+i) = (char)(j+65);
            }
        }
    }
    return plaintext;
}


char shiftCharacter(char character, int key, int table[], int direction){

    int charcode = (int)character;
    int indx, newindx = 0; 

    indx = getIndex(table, charcode);
    if (direction == UP){
        newindx = indx + key; 
        if (newindx > 61)
            newindx -=61;
    }
    else{
        newindx = indx - key; 
        if (newindx < 0)
            newindx +=61;
    }
    char shiftedChar = (char)table[newindx];
    int sz = sizeof(shiftedChar);
    return shiftedChar;
}


int getIndex(int table[], int charcode){

    for(int i=0; i< 62; i++){
        if (table[i]==charcode)
            return i; 
    }
}

char** getTabulaRecta(){

    char ** tabulaRecta = malloc(26 * sizeof(char*));
    int deccode; 
    for (int i =0 ; i < 26; ++i){
        tabulaRecta[i] = malloc(26 * sizeof(char));
        for (int j=0; j < 26 ;j++){
            deccode = 65+j+i;
            if (deccode > 90)
                deccode -= 26; 
            tabulaRecta[i][j] = (char)(deccode);

        }
        
    }
    return tabulaRecta;
}

char* adjustKey(char* key,int textSize){
    char* newkey = (char*)malloc(textSize * sizeof(char));
    int keySize = strlen(key);
    int tmp = 0;
    int md = 0;
    for (int i=0; i<textSize; i++){
        if (i < keySize){
            newkey[i] = key[i];
        }
        else{
            md = i/(keySize); 
            tmp = i-((md)*(keySize-1))-md;
            newkey[i] = key[tmp];
        }
    }
    return newkey;
    
}

char* generateKey(int textSize){

    FILE* fileData = fopen("/dev/urandom", "r");
    //int fileData = open("/dev/urandom", O_RDONLY);
    
    if (fileData < 0)
        printf("Error");

    char* key = (char*) malloc((textSize+1)*sizeof(char));

    //ssize_t ret = read(fileData, key, textSize);
    ssize_t ret = fread(key, 1, textSize, fileData); 
    
    return key;
}

void printHex(char* input){
    int size = strlen(input);
    for (int i=0; i < size; i++){
        printf("%02X ", input[i]);
    }
}
