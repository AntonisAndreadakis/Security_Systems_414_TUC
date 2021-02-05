#include "crypto.h"


/*

	** Initializers **

*/

/*
	Initializing the character set pool.
	A-Z -> indexes[ 0 - 25]
	a-z -> indexes[26 - 51]
	0-9 -> indexes[52 - 62]

*/

void poolInit()
{
	int initIndex = 48;  // 48 (dec) -> 0 (char)

	//initializing caps, 2*26 letters to assign + 10 numbers.
	for (int i = 0; i < POOL_SIZE; i++)
	{
		if(i < 10)				
			charPool[i] = initIndex + i;	  // initializing numbers
		else if(i < 36)
			charPool[i] = initIndex + i + 7;  // capitals
		else
			charPool[i] = initIndex + i + 13; // small	
		
	}

	

}

/*

	Generates an extended version of the original key to match length of plaintext.
	Input:		<char *orig>: The plaintext.
				<char *key>:  The key.
	Returns: 	The expanded key in a <char *>.
	Warning:

*/

char *extendKey(char *orig, char *key)
{
	

	//allocate some space.
	char *out = (char *)malloc(sizeof(char)*strlen(orig) + 1);
	
	//key's length is fine.
	if(strlen(key) >= strlen(orig))
		return key;
	
	//we need to expand the key by repetition.
	for(int i =0; i < strlen(orig); i++)
	{
		*(out + i) = *(key + i%strlen(key));
		
	}

	*(out + strlen(orig)) = '\0';


	return out;
}

/*
	
	** OPERATION HANDLERS **

*/

/*
	Prints a given string in hex format.
	Note: 	What printed on screen is the hex-equiavalent of the characters creating the string.
			Remember that each ASCII digit/char, has a 2-byte HEX-represantation so for a string of 5 charcters, 10 bytes will be displayed.

	Ex:		"lemon" -> 6c656d6f6e where l -> 6c, e -> 65, .., n -> 6e
	

*/
void printHex(char *key)
{
	//caching.
	char *curr = key;
	
	//offset count
	int off = 0;

	//parse the key, print as hex [2 digit align on console].
	while(off < strlen(key))
	{
		printf("%02x", *(curr + off));
		off++;
	}

	//change line.
	printf("\n");
	
	
}

/*
	Given a character, returns the respective index in charPool.
	Args:		The character to be tracked.
	Returns:	The respective index in the adjacent matrix or -1 if not found.
*/
int getPoolIndex(char c)
{
	//raw parsing is just a fun way of deciding.
	for (int i = 0; i < POOL_SIZE; i++)
	{	
		//if character given is present [A-Z, a-z, 0-9], return the index in the adjacent matrix.
		if(c == *(charPool + i))
			return i;
	}

	//return failure.
	return -1;
}

/*
	Given a character, returns the respective index in caps.
	Args:		The character to be tracked.
	Returns:	The respective index in the adjacent matrix or -1 if not found.
*/
int getCapsIndex(char c)
{
	//raw parsing is just a fun way of deciding.
	for (int i = 0; i < ALPHA_POOL_SIZE; i++)
	{	
		//if character given is present [A-Z], return the index in the adjacent matrix.
		if(c == *(caps + i))
			return i;
	}

	//return failure.
	return -1;
}


/*
	Returns a random alpha-arithmetic digit using a file descriptor on "/dev/urandom".
	More: "crypto.h"
*/
char getRandomDigit()
{

	//open the file descriptor "showing" the entropy-library.
	randGen = fopen(RANDOM_DEV, "rb");
	
	//fish the first digit out of the buffer.
	char digit = getc(randGen);


	// trapped until a valid digit appears.
	while(!isdigit(digit) && !isalpha(digit))
		digit = getc(randGen);

	//close open resources
	fclose(randGen);


	return digit;
}


/*

	Contructs a pseudo-random key of <siz> bytes.
	
*/
char *getRandomKey(int siz)
{
	char *key = (char *)malloc(siz + 1);

	//parse and create.
	for (int i = 0; i < siz; i++)
	{
		*(key +i) = getRandomDigit();
	}

	//manually terminate
	*(key + siz) = '\0';

	
	return key;

	
}


/*
	Formats a string in order to preserve ONLY 0-9, A-Z , a-z.
	More "crypto.h"
*/
char *formatInput(char *inp)
{
	//assume dummies will handle the code.
	if(!inp)
		return NULL;

	//offset counters, usage of separate offset counter for in,out makes control much more precise..
	//[think about the issue where we receive <space> as inp[0]..] !

	size_t posIn = 0;
	size_t posOut = 0;
	
	//reserve some space.
	
	char *out = (char *)malloc(sizeof(char)*strlen(inp)+1);
	
	//parse the input.
	while(posIn < strlen(inp))
	{
		//if legit, copy respective digit or char on output, else just skip.
		if(isdigit(*(inp + posIn)) || isalpha(*(inp + posIn)))
		{	
			*(out + posOut) = *(inp + posIn);
			posOut++;
			
		}
		posIn++;

	}

	//manually terminate string.
	*(out + posOut) = '\0';
	
	
	return out;



}



/*
	Reads user's input (STDIN) dynamically with the use of realloc,malloc. 
	Parses the input character - wise and then decides whether reallocation of memory needs to be done [run - time].
	Args: < * inp> a pointer to where data retrieved from STDIN wil be stored.

*/

char *readInput()
{
	//allocating a fixed length buffer and a ctr to keep track of the string's size.
	unsigned int actualLength = 0;
	char *inp = (char *)malloc(sizeof(char )*BUF_SIZE+1);




	//the current character in stdin.
	char curr = getchar();

	//avoid reading junks at start.
	while(curr < 32 || curr > 125)
		curr = getchar();


	//parse STDIN character-wise until newline is reached.
	while(curr != '\n' && curr != EOF)
	{
		
		//if limits are reached, reallocation must happen.
		if(actualLength >= BUF_SIZE)
			inp = realloc(inp, (actualLength + 10) * sizeof(char));

		//increment counter and store		
		inp[actualLength] = curr;
		actualLength++;

		//read again.
		curr = getchar();

	}

	//manually terminating is of TOP importance here.
	*(inp + actualLength) = '\0';

	//not much of error handling but at least there's is one..
	if(!inp)
		return NULL;
	return inp;



}


/*
	
		ENCRYPTION FUNCTIONS

*/




/*
	Encrypts the given string by bit-wise xoring with the given key.
	Args: 	<char *inp> pointer to a char array representing the actual plaintext.
			<char *key> pointer to a char array representing the encryption key [also known as pad/random pad].	
	Returns: The encrypted text/ciphertext in <char *> format.
	Warning: The ciphertext might include non-printable or "problematic" ASCII characters ['\0',' ', etc..]
	Tipp:	 Use <printHex()> in order to print the cipher for validation.

*/

char *encryptOTP(char *inp,  char *key)
{

	
	//reserving some space.
	char *out = (char *)malloc(sizeof(char )*strlen(key) + 1);
	
	//parse the input, xor with key.
	for (int i = 0; i < strlen(inp); ++i)
	{
		// only alphanumeric characters get to be converted, xoring with the key gives a ciphertext
		if(isalpha(*(inp+i)) || isdigit(*(inp + i)))
			*(out + i) = (char)(*(inp + i))^(*(key + i));
		else
		{
			fprintf(stderr, "Something went wrong upon encyption..\n");
			exit(-1);
		}


	}

	
	//manually appending terminating char.
	*(out + strlen(inp)) = '\0';

	return out; 
	
}


/*
	Decrypts the given string by bit-wise (reverse)xoring with the given key.
	Args: 	<char *inp> pointer to a char array representing the ciphertext.
			<char *key> pointer to a char array representing the encryption key [also known as pad/random pad].	
	Returns: The decrypted text/original in <char *> format.
	

*/

char *decryptOTP(char *inp,  char *key)
{
	//reserving some space.
	char *out = (char *)malloc(sizeof(char )*strlen(key) + 1);
	

	//parse the input, reverse xoring will reveal the secret.
	for (int i = 0; i < strlen(inp); ++i)
		*(out + i) = (char)(*(key + i))^(*(inp + i));
	

		

	//manually appending terminating char.
	*(out + strlen(inp)) = '\0';

	return out; 

}


/*
	Encrypts the given string with Ceasar method via shifting on the alphabet <key> times.
	Args: 	<char *inp> pointer to a char array representing the actual plaintext.
			<int key>   number of shifts.	
	Returns: The encrypted text/ciphertext in <char *> format.
	Warning: The alphabet used is constant in space [0-9A-Za-z]

*/

char *encryptCeasar(char *inp, int k)
{

	//allocating some space.
	char *out = (char *)malloc(sizeof(char )*strlen(inp) + 1);

	
	//parsing input byte-wise.
	for (int i = 0; i < strlen(inp); i++)
	{
			// get the adjacent index in Ceasar's cube.
			unsigned int adjIndex = getPoolIndex(inp[i]) + k;

			// adjust bounds if needed.
			if(adjIndex >= POOL_SIZE)
				adjIndex = adjIndex%POOL_SIZE;

			//append 
			*(out + i) = *(charPool + adjIndex);
	}

	//manually terminate string.
	*(out + strlen(inp)) = '\0';



	return out;

}


/*
	Decrypts the given string with Ceasar method via shifting on the alphabet <key> times.
	Args: 	<char *inp> pointer to a char array representing the ciphertext.
			<int key>   number of shifts.	
	Returns: The decrypted text/original <char *> format.
	Warning: The alphabet used is constant in space [0-9A-Za-z]

*/



char *decryptCeasar(char *inp, int k)
{

	//allocating some space.
	char *out = (char *)malloc(sizeof(char )*strlen(inp) + 1);


	
	//parsing input byte-wise.
	for (int i = 0; i < strlen(inp); i++)
	{
			// get the adjacent index in Ceasar's cube.
			int adjIndex = getPoolIndex(inp[i]) - k;
		
			
			// adjust bounds if needed.
			while(adjIndex < 0)
				adjIndex = adjIndex + POOL_SIZE;

			
			//append 
			*(out + i) = *(charPool + adjIndex);
	}

	//manually terminate string.
	*(out + strlen(inp)) = '\0';



	return out;

}


/*
	Encrypts the given string with Vigenere method via modulo sums.
	Args: 	<char *inp> pointer to a char array representing the actual plaintext.
			<char *key> the key used for encryption.	
	Returns: The encrypted text/ciphertext in <char *> format.
	Warning: The alphabet used is ONLY CAPITALS [A-Z]
	Tipp:	 You migh want to extend the key at first via extendKey().

*/

char *encryptVigenere(char *inp, char *key)
{
	//allocate some space.
	char *out = (char *)malloc(sizeof(char )*strlen(inp) + 1);

	//parse the input bytewise.
	for (int i = 0; i < strlen(inp); i++)
	{
		//convert in range 0-25 and transfer to ASCII capital indexes [+65]
		unsigned int off = (*(inp + i) + *(key + i))%26 + 65;

		//append.
		*(out + i) = (char )off;



	}

	//manually terminate.
	*(out + strlen(inp)) = '\0';

	return out;
}


/*
	Decrypts the given string with Vigenere method via modulo sums.
	Args: 	<char *inp> pointer to a char array representing the ciphertext.
			<char *key> the key used for encryption.	
	Returns: The decrypted text/plairtext in <char *> format.
	Warning: The alphabet used is ONLY CAPITALS [A-Z]

*/

char *decryptVigenere(char *inp, char *key)
{
	//allocate some space.
	char *out = (char *)malloc(sizeof(char )*strlen(inp) + 1);

	//parse the input bytewise.
	for (int i = 0; i < strlen(inp); i++)
	{
		//convert in range 0-25 and transfer to ASCII capital indexes [+65]
		unsigned int off = (*(inp + i) - *(key + i) + 26)%26 + 65;


		//append.
		*(out + i) = (char )off;



	}

	//manually terminate.
	*(out + strlen(inp)) = '\0';

	return out;
}



