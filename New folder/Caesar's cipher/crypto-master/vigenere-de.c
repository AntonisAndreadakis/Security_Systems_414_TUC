/*
 * Vigenere cipher uses keyword to decrypt.
 *
 * All performed in capitals
 *
 * by jostha :: https://github.com/jostha
 */

#include <stdio.h>
#include <string.h>

void upcase(char []);

int main(){

	int 	x;
	char 	msg[255],
			key[255];

	printf ("\nEnter text to decode: ");
	gets(msg);
	printf ("\nEnter decryption key: ");
	gets(key);

	// Conv to CAPS 
	upcase(msg);
	upcase(key);

	printf ("\nEncrypted message is : %s ", msg);
	printf ("\n              Key is : %s ", key);

	// Decrypt (could be mixed with above if required)
	int	keypos=0,
			keylen = strlen(key);
	char 	de[strlen(msg)];

	for (x=0; msg[x] != '\0'; x++){
		de[x] = ' ';	// clear cruft before populating
		if (msg[x] >= 'A' && msg[x] <= 'Z') {
			de[x] = (( msg[x] - key[keypos] + 26) % 26) + 'A';
			keypos ++;
			if (keypos == keylen){
				keypos = 0;
			}
		}
	}
	de[x] = '\0';

	printf ("\nDecrypted message is : %s\n", de);

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
