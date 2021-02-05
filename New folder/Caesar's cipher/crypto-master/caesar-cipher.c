/*
 * Caesar cipher increased each character by one place in alphabet.
 *
 * Be easy enough to hack this and provide a z value for position shift
 *
 * by jostha :: https://github.com/jostha
 */

#include <stdio.h>
#include <string.h>

int main(){
	char cc[255];
	printf ("Enter text to encode: ");
	fgets(cc, 255, stdin);

	for (int a=0; cc[a] != '\0'; ++a){
		if ((cc[a] >= 'a' && cc[a] <= 'z') ||
			(cc[a] >= 'A' && cc[a] <= 'Z')){
			// Has to be letter from alphabet to get here
			if (cc[a] == 'z' || cc[a] == 'Z'){
				cc[a] -= 25;
			}
			else {	  
				cc[a] += 1;
			}
		}
	}

	printf ("Encoded is: %s", cc);

	return 0;
}

