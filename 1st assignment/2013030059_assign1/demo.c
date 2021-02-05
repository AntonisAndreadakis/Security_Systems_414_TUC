     #include <stdio.h>   
     #include <stdlib.h>  
     #include <assert.h>  
     #include <string.h>
     #include <ctype.h>
     #include "simple_crypto.c"
     #define BUFFER_SIZE 2048
//secret
//hello
//4
//ATTACKATDAWN
//LEMONLEMONLE
int main(){
        printf("\tHello! You are about to use a decryption method.\n");
        printf("\tMethod name: One Time Pad.\n");
        printf("\tYou are asked to provide a passphrase.\n");
        printf("\tUse letters (lower or upper), numbers (0-9) or both letters and numbers.\n");        
        printf("\nPlease enter your desired message for encryption: \n");
        char o[BUFFER_SIZE];
        //get input string:
        scanf("%[^\n]s", o);
        otp(o);
        printf("\n");
        printf("\tNow you are about to use a second decryption method.\n");
        printf("\tGive a sequence of characters as one string (no whitespace).\n");
        printf("\tUse letters (lower or upper), numbers (0-9) or both letters and numbers.\n");
        printf("\tMethod name: Caesar's cipher.\n");

        char cae[BUFFER_SIZE];
        int sh;
        printf ("\nEnter text to encode: \n");
        //get input string:
        scanf("%s", cae);
        printf ("Enter secret key for encryption (number): \n");
        scanf("%d", &sh);
        caesar(cae, sh);
        printf("\n");
        printf("\tNow you are about to use the last decryption method.\n");
        printf("\tUse only capital letters.\n");
        printf("\tMethod name: Vigenere's cipher.\n");

        char vig[BUFFER_SIZE]; 
        char key[BUFFER_SIZE];
        printf ("\nEnter text to encode: \n");
        //get input string:
        scanf("%s", vig);
        printf ("Your key must be same length (as long as your input).\n");
        printf ("Enter secret key for encryption: \n");
        scanf("%s", key);
        vigenere(vig, key);
return 0;
}
