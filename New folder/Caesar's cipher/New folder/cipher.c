#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

char *encrypt(char *string, short shift) {
    size_t len = strlen(string);
    unsigned short i;
    char *new = NULL;
    new = calloc(len + 1, sizeof(char));

    for (i = 0; i < len; i++) {
        char c = string[i];
        int c_int = (int) c;
        
        if (!isalpha(c_int)) {
            new[i] = string[i];
            continue;
        }
        
        if (isupper(c_int)) {
            new[i] = (((c_int - 'A') + shift) % 26) + 'A';
            if (new[i] < 'A') {
                new[i] = 'Z' + 1 - ('A' - new[i]);
            }
        } else {
            new[i] = (((c_int - 'a') + shift) % 26) + 'a';
            if (new[i] < 'a') {
                new[i] = 'z' + 1 - ('a' - new[i]);
            }
        }
    }
    return new;
}

char *decrypt(char *string, short shift) {
    return encrypt(string, -shift);
}

void print_shift(short shift) {
    printf("Alphabet:\t");
    unsigned char i;
    for (i = 'a'; i <= 'z'; i++) {
        printf("%c ", i);
    }
    printf("\nShifted:\t");
    for (i = 0; i < 26; i++) {
        printf("%c ", ((i + shift) % 26) + 'a');
    }
    printf("\n");
}
