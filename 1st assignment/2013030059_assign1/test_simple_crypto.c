#include "simple_crypto.h"

#include <stdio.h>
#include <string.h>

#define CHECK(condition)                                                        \
	do {                                                                      \
		if (!(condition)) {                                                 \
			fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,      \
			        #condition);                                          \
			return 1;                                                     \
		}                                                                 \
	} while (0)

static int test_otp(void)
{
	static const unsigned char plain[] = {0x00, 0x41, 0x7f, 0xff};
	static const unsigned char key[] = {0xaa, 0x55, 0x0f, 0xf0};
	static const unsigned char expected[] = {0xaa, 0x14, 0x70, 0x0f};
	unsigned char cipher[sizeof(plain)];
	unsigned char recovered[sizeof(plain)];
	unsigned char generated[32];

	otp_xor(plain, key, cipher, sizeof(plain));
	CHECK(memcmp(cipher, expected, sizeof(expected)) == 0);
	otp_xor(cipher, key, recovered, sizeof(cipher));
	CHECK(memcmp(recovered, plain, sizeof(plain)) == 0);
	CHECK(otp_generate_key(generated, sizeof(generated)) == 0);
	CHECK(otp_generate_key(NULL, 0) == 0);
	CHECK(otp_generate_key(NULL, 1) == -1);
	return 0;
}

static int test_caesar(void)
{
	static const char alphabet[] = SIMPLE_CRYPTO_ALPHABET;
	static const char rotated[] =
		"123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0";
	char cipher[128];
	char plain[128];
	char in_place[16] = "hello";

	CHECK(crypto_is_alnum62(alphabet));
	CHECK(!crypto_is_alnum62(""));
	CHECK(!crypto_is_alnum62("has space"));
	CHECK(caesar_encrypt(alphabet, 1, cipher, sizeof(cipher)) == 0);
	CHECK(strcmp(cipher, rotated) == 0);
	CHECK(caesar_decrypt(cipher, 1, plain, sizeof(plain)) == 0);
	CHECK(strcmp(plain, alphabet) == 0);
	CHECK(caesar_encrypt("hello", 4, cipher, sizeof(cipher)) == 0);
	CHECK(strcmp(cipher, "lipps") == 0);
	CHECK(caesar_encrypt("z", 1, cipher, sizeof(cipher)) == 0);
	CHECK(strcmp(cipher, "0") == 0);
	CHECK(caesar_encrypt("Az9", 125, cipher, sizeof(cipher)) == 0);
	CHECK(caesar_decrypt(cipher, 125, plain, sizeof(plain)) == 0);
	CHECK(strcmp(plain, "Az9") == 0);
	CHECK(caesar_encrypt(in_place, 4, in_place, sizeof(in_place)) == 0);
	CHECK(strcmp(in_place, "lipps") == 0);
	CHECK(caesar_encrypt("bad!", 1, cipher, sizeof(cipher)) == -1);
	CHECK(caesar_encrypt("abc", -1, cipher, sizeof(cipher)) == -1);
	CHECK(caesar_encrypt("abc", 1, cipher, 3) == -1);
	return 0;
}

static int test_vigenere(void)
{
	char cipher[128];
	char plain[128];
	char in_place[16] = "ATTACK";

	CHECK(vigenere_encrypt("ATTACKATDAWN", "LEMON", cipher, sizeof(cipher)) == 0);
	CHECK(strcmp(cipher, "LXFOPVEFRNHR") == 0);
	CHECK(vigenere_decrypt(cipher, "LEMON", plain, sizeof(plain)) == 0);
	CHECK(strcmp(plain, "ATTACKATDAWN") == 0);
	CHECK(vigenere_encrypt(in_place, "LEMON", in_place, sizeof(in_place)) == 0);
	CHECK(strcmp(in_place, "LXFOPV") == 0);
	CHECK(vigenere_encrypt("lower", "KEY", cipher, sizeof(cipher)) == -1);
	CHECK(vigenere_encrypt("UPPER", "key", cipher, sizeof(cipher)) == -1);
	CHECK(vigenere_encrypt("UPPER", "", cipher, sizeof(cipher)) == -1);
	CHECK(vigenere_encrypt("UPPER", "KEY", cipher, 5) == -1);
	return 0;
}

int main(void)
{
	CHECK(test_otp() == 0);
	CHECK(test_caesar() == 0);
	CHECK(test_vigenere() == 0);
	puts("all simple_crypto tests passed");
	return 0;
}
