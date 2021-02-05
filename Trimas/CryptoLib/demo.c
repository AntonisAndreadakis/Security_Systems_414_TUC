#include "simple_crypto.h"

void main()
{	
	char* plaintext;
	char* keyOTP;

	printf("\n[OTP] input: ");
	plaintext = nonBufferedOvfInput();

	keyOTP = randomGenerator(plaintext);

	printf("[OTP] encrypted: ");
    otp_encrypt_decrypt(plaintext,keyOTP);
    printf("\n");

    printf("[OTP] decrypted: ");
    otp_encrypt_decrypt(plaintext,keyOTP);
    printf("\n");

    free(plaintext);
    plaintext = NULL;
/////////////////////////////////////////////////////////////////////
    printf("\n[Caesars] input: ");
	plaintext = nonBufferedOvfInput();

	printf("[Caesars] key: ");
    int keyCaesar;
    scanf("%d",&keyCaesar);

    ceasars_cipher(plaintext,keyCaesar);
 
    free(plaintext);
    plaintext = NULL;
/////////////////////////////////////////////////////////////////////
    char* keyVigenere,*text;
    getchar();
    printf("\n[Vigenere] input: ");
    text = nonBufferedOvfInputUpper();

    printf("[Vigenere] key: ");
    keyVigenere = nonBufferedOvfInputUpper();

    vigenere(text,keyVigenere);
    printf("\n");
    
    free(text);
    free(keyVigenere);
    return;

}