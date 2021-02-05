#include <cs50.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

int main (int argc, string argv[])
{
    if (argc != 2) //check if the user inputs has more than 1 key
    {
        printf("Usage: ./caesar key\n");
        return 1;
    }

    int key = atoi(argv[1]);
    
    if (key < 0) //check if the key is less than 0
    {
        printf("Usage: ./caesar key\n");
        return 1;
    }
    
    int characterskey = strlen(argv[1]);
    
    for (int i = 0; i < strlen(argv[1]); i++) //check if the key is not a number

    if (!(isdigit(argv[1][i])))
    {
        printf("Usage: ./caesar key\n");
        return 1;
    }
      
string text = get_string("Plaintext: "); //input for the user`s plaintext
printf("ciphertext: ");
for (int j = 0; j < strlen(text); j++)
    
    if islower(text[j])
    {
        printf("%c", ((((text[j] + key) - 97) % 26) + 97));
    }
    
    else if isupper(text[j])
    {
        printf("%c", ((((text[j] + key) - 65) % 26) + 65));
    }

    else
    {
        printf("%c", text[j]);
    }
    
    printf("\n");
    return 0;    
}
