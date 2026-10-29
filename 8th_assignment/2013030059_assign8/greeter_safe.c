/* Safe comparison target. The original Greeter.c remains the intentional lab. */
#include <stdio.h>

int main(void) {
    char name[32];
    size_t length = 0;
    int ch;
    puts("What is your name?");
    while ((ch = getchar()) != EOF && ch != '\n') {
        if (ch < 32 || ch > 126 || length == sizeof(name) - 1) {
            fputs("Name must contain 1 to 31 printable ASCII characters.\n", stderr);
            return 1;
        }
        name[length++] = (char)ch;
    }
    if (ferror(stdin) || !length) { fputs("A name is required.\n", stderr); return 1; }
    name[length] = '\0';
    printf("Hello %s, have a nice day.\n", name);
    return 0;
}
