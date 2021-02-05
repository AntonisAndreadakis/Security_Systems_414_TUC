/*
 * Vigenere cipher uses keyword to encrypt.
 *
 * All performed in capitals
 *
 * by jostha :: https://github.com/jostha
 */

// TODO : Decrypter

#include <stdio.h>
#include <string.h>

void upcase(char []);

int main(){

	int 	x;
	char 	msg[255],
			key[255];

	printf ("\nEnter text to encode: ");
	gets(msg);
	printf ("\nEnter encryption key: ");
	gets(key);

	// Conv to CAPS
	upcase(msg);
	upcase(key);

	printf ("\nMessage is : %s ", msg);
	printf ("\n    Key is : %s ", key);

	// Encrypt (could be mixed with above if required)
	int	keypos=0,
			keylen = strlen(key);
	char 	enc[strlen(msg)];

	for (x=0; msg[x] != '\0'; x++){
		enc[x] = ' ';	// clear cruft before populating
		if (msg[x] >= 'A' && msg[x] <= 'Z') {
			enc[x] = (( msg[x] + key[keypos] ) % 26) + 'A';
			keypos ++;
			if (keypos == keylen){
				keypos = 0;
			}
		}
	}
	enc[x] = '\0';

	printf ("\nEncrypted message is: %s\n", enc);

	return 0;
}

void upcase(char inp[]){
	int i=0;
	while (inp[i] != '\0') {
		if (inp[i] >= 'a' && inp[i] <= 'z') {
			inp[i] = inp[i] - 32;
		}
		i++;
	}
}
