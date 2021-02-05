#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include "simple_crypto.h"

char* fixString(char* input, int capsFlag);

int main(){
    char *plaintext;
    char *input;
    size_t bufsize = 250;
    size_t characters; 
    char* otpKey, *otpCypherText, *otpDecryptedText; 
    int caesarKey =0; char *caesarCypherText, *caesarDecryptedText;  
    char *vigenereKey, *vigenereCyphertext, *vigenereDecryptedText; 
 
    printf("\n[OTP]input: ");
    input = (char *)malloc(bufsize * sizeof(char));
    characters = getline(&input,&bufsize,stdin);
    plaintext = fixString(input, CAPS_OFF);
    otpKey = generateKey(strlen(plaintext));
    otpCypherText = oneTimePadEncrypt(plaintext, otpKey);
    printf("\n[OTP]encrypted: ");
    printHex(otpCypherText);
    otpDecryptedText = oneTimePadDecrypt(otpCypherText, otpKey);
    printf("\n[OTP]decrypted: %s", otpDecryptedText);

    //scanf("\n[Caesars]input:%d", &caesarKey); 
    caesarKey = 4; 
    printf("\n[Caesars]key: %d", caesarKey);
    caesarCypherText = caesarCipherEncrypt(plaintext, caesarKey);
    printf("\n[Caesars]encrypted: %s", caesarCypherText);
    caesarDecryptedText = caesarCipherDecrypt(caesarCypherText, caesarKey);
    printf("\n[Caesars]decrypted: %s", caesarDecryptedText);
    /*
    printf("\n[Vigenere]input: ");
    memset(input,0,strlen(input));
    characters = 0;
    characters = getline(&input,&bufsize,stdin);
    vigenereKey = fixString(input, CAPS_ON); 
    printf("\n[Vigenere]key: %s", vigenereKey);
    vigenereCyphertext = vigenereCipherEncrypt(plaintext, "LEMON");
    printf("\n[Vigenere]encrypted: %s", vigenereCyphertext);
    vigenereDecryptedText = vigenereCipherDecrypt(vigenereCyphertext, "LEMON");
    printf("\n[Vigenere]decrypted: %s", vigenereDecryptedText);
    */
}

char* fixString(char* input, int capsFlag){
    int inputSize = strlen(input);
    char *fixedInput = (char *)malloc((inputSize+1)*sizeof(char)); 
    int croppedSize =0;
    if (capsFlag == 0){
        for (int i=0; i< inputSize; i++){
            if (((int)input[i] >= 48 && (int)input[i] <= 57) || ((int)input[i] >= 65 && (int)input[i] <= 90) 
            || ((int)input[i] >= 97 && (int)input[i] <= 122)){
                *(fixedInput+croppedSize) = input[i];
                croppedSize+=1;
            }
        }
        fixedInput = realloc(fixedInput, (croppedSize+1)*sizeof(char));
        return fixedInput;
    }else{
        for (int i=0; i< inputSize; i++){
            if ((int)input[i] > 65 && (int)input[i] < 90) 
            {
                *(fixedInput+croppedSize) = input[i];
                croppedSize+=1;
            }
        }
        fixedInput = realloc(fixedInput, (croppedSize+1)*sizeof(char));
        return fixedInput;
    } 
    
     
}