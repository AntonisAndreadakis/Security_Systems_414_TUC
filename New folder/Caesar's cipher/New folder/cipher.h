#ifndef CIPHER_HEADER
#define CIPHER_HEADER

/**
 * Shifts a string a certain number down the alphabet to encode a string.
 * I.E. (Shift of 1)
 *      Hello
 *      Ifmmp
 * Returns a pointer to a char array containing the encrypted string.
 */
char *encrypt(char *string, short shift);

/**
 * Shifts a string a certain number up the alphabet to decode a string.
 * I.E. (Shift of 1)
 *      Ifmmp
 *      Hello
 * Returns a pointer to a char array containing the decrypted string.
 */
char *decrypt(char *string, short shift);

/**
 * Prints a visual representation for the entire alphabet of a certain shift.
 */
void print_shift(short shift);

#endif /* CIPHER_HEADER */
