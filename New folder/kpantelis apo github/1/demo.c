#include "crypto.h"



int main()
{

	char *plain = NULL;
	char *plainV = NULL;
	char *key = NULL;
	char *enc = NULL;
	char *orig = NULL;
	char *some = NULL;
	int k;
	

	/*
		One-Time-Pad.
	
	*/
	
	printf("[OTP] input: ");
	plain = readInput();
	plain = formatInput(plain);
	
   	key = getRandomKey(strlen(plain));
   	
   	enc = encryptOTP(plain, key);

   	printf("[OTP] encrypted: ");
   	printHex(enc);

   	orig = decryptOTP(enc, key);
   	printf("[OTP] decrypted: %s\n", orig);

   	
   

   	/*
		
		Ceasar's Algo.
	*/
	

   	
   	printf("[Ceasars] input: ");
   	plain = readInput();
   	plain = formatInput(plain);

   	printf("[Ceasars] key: ");
   	scanf("%d", &k);

   	poolInit();



   	enc = encryptCeasar(plain,k);
   	printf("[Ceasars] encrypted: %s\n", enc);


   	orig = decryptCeasar(enc, k);
   	printf("[Ceasars] decrypted: %s\n", orig);
   	
  
   	
	
   	

   	/*
   		Vigenere Algo.
   	
   	*/
   	
   

   	printf("[Vigenere] input: ");
   	plainV = readInput();
   	plainV = formatInput(plainV);
   

   	printf("[Vigenere] key: ");
   	key = readInput();
   	key = formatInput(key);
   	key = extendKey(plainV,key);

   	enc = encryptVigenere(plainV, key);
   	printf("[Vigenere] encrypted: %s\n", enc);

   	orig = decryptVigenere(enc, key);
   	printf("[Vigenere] decrypted: %s\n", orig);


  	//free up some resources.

  	free(orig);
  	free(key);
  	free(plain);
  	free(plainV);
  	free(enc);

   	
	

	return 0;
}
