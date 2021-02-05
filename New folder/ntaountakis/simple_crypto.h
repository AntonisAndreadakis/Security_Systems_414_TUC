#define ALL_ASCII_COUNT 62
#define UP 1
#define DOWN 0
#define A_ASCII_CODE 65
#define CAPS_ON 1
#define CAPS_OFF 0
char* oneTimePadEncrypt(char* cyphertext, char* key);
char* oneTimePadDecrypt(char* cyphertext, char* key);
char* caesarCipherEncrypt(char* plaintext, int key);
char* caesarCipherDecrypt(char* cyphertext, int key);
char* vigenereCipherEncrypt(char* plaintext, char* key);
char* vigenereCipherDecrypt(char* cyphertext, char* key);

char* generateKey();
int getIndex(int array[], int decnum);
char shiftCharacter(char character, int key, int asciiTable[], int direction);
char** getTabulaRecta();
char* adjustKey(char* key,int textSize);
void printHex(char* input);