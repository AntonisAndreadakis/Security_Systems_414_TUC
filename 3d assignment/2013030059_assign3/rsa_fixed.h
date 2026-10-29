#ifndef RSA_FIXED_H
#define RSA_FIXED_H
int rsa_keygen(void);
int rsa_encrypt(const char *, const char *, const char *);
int rsa_decrypt(const char *, const char *, const char *);
#endif
