#if 0 /* Original submission retained for review. */
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
#endif

#include "simple_crypto.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_line(char *buffer, size_t capacity)
{
	size_t length;
	int character;

	if (fgets(buffer, (int)capacity, stdin) == NULL)
		return -1;
	length = strlen(buffer);
	if (length > 0 && buffer[length - 1] == '\n') {
		buffer[--length] = '\0';
		if (length > 0 && buffer[length - 1] == '\r')
			buffer[length - 1] = '\0';
		return 0;
	}
	if (feof(stdin))
		return 0;
	while ((character = getchar()) != '\n' && character != EOF) {
		/* Drain an overlong input line. */
	}
	return -1;
}

static int parse_shift(const char *text, int *shift)
{
	char *end;
	long value;

	errno = 0;
	value = strtol(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || value < 0 || value > INT_MAX)
		return -1;
	*shift = (int)value;
	return 0;
}

static void print_hex(const unsigned char *bytes, size_t length)
{
	size_t i;

	for (i = 0; i < length; ++i)
		printf("%02x", bytes[i]);
}

int main(void)
{
	char otp_input[SIMPLE_CRYPTO_BUFFER_SIZE];
	char caesar_input[SIMPLE_CRYPTO_BUFFER_SIZE];
	char caesar_cipher[SIMPLE_CRYPTO_BUFFER_SIZE];
	char caesar_plain[SIMPLE_CRYPTO_BUFFER_SIZE];
	char shift_text[64];
	char vigenere_input[SIMPLE_CRYPTO_BUFFER_SIZE];
	char vigenere_key[SIMPLE_CRYPTO_BUFFER_SIZE];
	char vigenere_cipher[SIMPLE_CRYPTO_BUFFER_SIZE];
	char vigenere_plain[SIMPLE_CRYPTO_BUFFER_SIZE];
	unsigned char otp_key[SIMPLE_CRYPTO_BUFFER_SIZE];
	unsigned char otp_cipher[SIMPLE_CRYPTO_BUFFER_SIZE];
	unsigned char otp_plain[SIMPLE_CRYPTO_BUFFER_SIZE];
	size_t otp_length;
	int shift;

	if (read_line(otp_input, sizeof(otp_input)) != 0 || !crypto_is_alnum62(otp_input)) {
		fprintf(stderr, "OTP input must be a non-empty 0-9/A-Z/a-z string\n");
		return 1;
	}
	otp_length = strlen(otp_input);
	if (otp_generate_key(otp_key, otp_length) != 0) {
		perror("/dev/urandom");
		return 1;
	}
	otp_xor((const unsigned char *)otp_input, otp_key, otp_cipher, otp_length);
	otp_xor(otp_cipher, otp_key, otp_plain, otp_length);
	otp_plain[otp_length] = '\0';
	printf("[OTP] input: %s\n", otp_input);
	printf("[OTP] encrypted: ");
	print_hex(otp_cipher, otp_length);
	putchar('\n');
	printf("[OTP] decrypted: %s\n", (char *)otp_plain);

	if (read_line(caesar_input, sizeof(caesar_input)) != 0 ||
	    read_line(shift_text, sizeof(shift_text)) != 0 ||
	    parse_shift(shift_text, &shift) != 0 ||
	    caesar_encrypt(caesar_input, shift, caesar_cipher, sizeof(caesar_cipher)) != 0 ||
	    caesar_decrypt(caesar_cipher, shift, caesar_plain, sizeof(caesar_plain)) != 0) {
		fprintf(stderr, "Caesar input must be 0-9/A-Z/a-z and its key a non-negative integer\n");
		return 1;
	}
	printf("[Caesars] input: %s\n", caesar_input);
	printf("[Caesars] key: %d\n", shift);
	printf("[Caesars] encrypted: %s\n", caesar_cipher);
	printf("[Caesars] decrypted: %s\n", caesar_plain);

	if (read_line(vigenere_input, sizeof(vigenere_input)) != 0 ||
	    read_line(vigenere_key, sizeof(vigenere_key)) != 0 ||
	    vigenere_encrypt(vigenere_input, vigenere_key,
	                     vigenere_cipher, sizeof(vigenere_cipher)) != 0 ||
	    vigenere_decrypt(vigenere_cipher, vigenere_key,
	                     vigenere_plain, sizeof(vigenere_plain)) != 0) {
		fprintf(stderr, "Vigenere input and key must be non-empty uppercase A-Z strings\n");
		return 1;
	}
	printf("[Vigenere] input: %s\n", vigenere_input);
	printf("[Vigenere] key: %s\n", vigenere_key);
	printf("[Vigenere] encrypted: %s\n", vigenere_cipher);
	printf("[Vigenere] decrypted: %s\n", vigenere_plain);
	return 0;
}
