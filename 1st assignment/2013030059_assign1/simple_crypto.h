
#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H

#include <stddef.h>

#define SIMPLE_CRYPTO_BUFFER_SIZE 2048U
#define SIMPLE_CRYPTO_ALPHABET "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
#define SIMPLE_CRYPTO_ALPHABET_SIZE 62

/* Return 1 only when text is non-empty and contains characters from the
 * assignment's 62-character alphabet. */
int crypto_is_alnum62(const char *text);

/* Copy only the characters of input that belong to the 62-character
 * alphabet into output (which must be at least strlen(input)+1 bytes),
 * NUL-terminate it, and return the filtered length. Used for OTP, where
 * XOR is not closed over the alphabet so a skipped character cannot be
 * told apart from a transformed one by its value alone (unlike Caesar,
 * see caesar_encrypt/caesar_decrypt). */
size_t crypto_filter_alnum62(const char *input, char *output);

/* Fill key with cryptographically random bytes from /dev/urandom. */
int otp_generate_key(unsigned char *key, size_t length);

/* OTP encryption and decryption are the same length-aware XOR operation. */
void otp_xor(const unsigned char *input, const unsigned char *key,
             unsigned char *output, size_t length);

/* Caesar operates on the single ordered alphabet 0-9, A-Z, a-z; a character
 * outside that alphabet (space, punctuation, '\n', ...) is left unchanged in
 * place, as the assignment's "skip" rule requires, and the shift must be
 * non-negative. */
int caesar_encrypt(const char *input, int shift, char *output, size_t capacity);
int caesar_decrypt(const char *input, int shift, char *output, size_t capacity);

/* Vigenere accepts uppercase A-Z text and a non-empty uppercase A-Z key. */
int vigenere_encrypt(const char *input, const char *key,
                     char *output, size_t capacity);
int vigenere_decrypt(const char *input, const char *key,
                     char *output, size_t capacity);

#endif
