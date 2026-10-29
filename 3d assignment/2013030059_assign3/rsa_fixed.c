#include "rsa_fixed.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LIMIT 255

static size_t gcd_value(size_t a, size_t b)
{
	while (b) { size_t r = a % b; a = b; b = r; }
	return a;
}

static size_t mod_inverse(size_t a, size_t modulus)
{
	int64_t t = 0, nt = 1, r = (int64_t)modulus, nr = (int64_t)(a % modulus);
	while (nr) {
		int64_t q = r / nr, next_t = t - q * nt, next_r = r - q * nr;
		t = nt; nt = next_t; r = nr; nr = next_r;
	}
	if (r != 1) return 0;
	if (t < 0) t += (int64_t)modulus;
	return (size_t)t;
}

static size_t mod_power(size_t base, size_t exponent, size_t modulus)
{
	size_t result = 1;
	if (!modulus) return 0;
	base %= modulus;
	while (exponent) {
		if (exponent & 1U) result = (result * base) % modulus;
		base = (base * base) % modulus;
		exponent >>= 1;
	}
	return result % modulus;
}

static size_t *prime_pool(size_t *count)
{
	unsigned char sieve[LIMIT + 1] = {0};
	size_t *values, i, j, n = 0;
	memset(sieve + 2, 1, LIMIT - 1);
	for (i = 2; i <= LIMIT / i; ++i)
		if (sieve[i]) for (j = i * i; j <= LIMIT; j += i) sieve[j] = 0;
	for (i = 2; i <= LIMIT; ++i) n += sieve[i] != 0;
	values = malloc(n * sizeof(*values));
	if (!values) return NULL;
	for (i = 2, j = 0; i <= LIMIT; ++i) if (sieve[i]) values[j++] = i;
	*count = n; return values;
}

static int write_key(const char *path, size_t n, size_t exponent)
{
	FILE *f = fopen(path, "wb");
	int ok;
	if (!f) { fprintf(stderr, "error: %s: %s\n", path, strerror(errno)); return 0; }
	ok = fwrite(&n, sizeof n, 1, f) == 1 && fwrite(&exponent, sizeof exponent, 1, f) == 1;
	if (fclose(f)) ok = 0;
	if (!ok) fprintf(stderr, "error: cannot write %s\n", path);
	return ok;
}

static int read_key(const char *path, size_t *n, size_t *exponent)
{
	FILE *f = fopen(path, "rb");
	int extra, ok;
	if (!f) { fprintf(stderr, "error: %s: %s\n", path, strerror(errno)); return 0; }
	ok = fread(n, sizeof *n, 1, f) == 1 && fread(exponent, sizeof *exponent, 1, f) == 1;
	extra = fgetc(f);
	if (fclose(f)) ok = 0;
	if (!ok || extra != EOF || *n <= UCHAR_MAX || !*exponent) {
		fprintf(stderr, "error: invalid key file %s\n", path); return 0;
	}
	return 1;
}

int rsa_keygen(void)
{
	size_t count, *primes = prime_pool(&count), p, q, n, phi, e = 0, d, i, a, b;
	if (!primes) { fprintf(stderr, "error: key generation allocation failed\n"); return 0; }
	srand((unsigned)time(NULL) ^ (unsigned)clock());
	do { a = (size_t)rand() % count; b = (size_t)rand() % count;
		p = primes[a]; q = primes[b]; } while (a == b || p * q <= UCHAR_MAX);
	n = p * q; phi = (p - 1) * (q - 1);
	for (i = 0; i < count; ++i)
		if (primes[i] > 1 && primes[i] < phi && gcd_value(primes[i], phi) == 1) { e = primes[i]; break; }
	d = mod_inverse(e, phi); free(primes);
	if (!e || !d) { fprintf(stderr, "error: exponent derivation failed\n"); return 0; }
	/* The assignment explicitly requires public=(n,d), private=(n,e). */
	if (!write_key("public.key", n, d)) return 0;
	if (!write_key("private.key", n, e)) { remove("public.key"); return 0; }
	return 1;
}

int rsa_encrypt(const char *in_path, const char *out_path, const char *key_path)
{
	size_t n, exponent, encrypted; int byte, ok = 0; FILE *in = NULL, *out = NULL;
	if (!read_key(key_path, &n, &exponent)) return 0;
	in = fopen(in_path, "rb");
	if (!in) { fprintf(stderr, "error: %s: %s\n", in_path, strerror(errno)); goto done; }
	out = fopen(out_path, "wb");
	if (!out) { fprintf(stderr, "error: %s: %s\n", out_path, strerror(errno)); goto done; }
	while ((byte = fgetc(in)) != EOF) {
		encrypted = mod_power((unsigned char)byte, exponent, n);
		if (fwrite(&encrypted, sizeof encrypted, 1, out) != 1) goto done;
	}
	if (!ferror(in)) ok = 1;
done:
	if (in && fclose(in)) ok = 0;
	if (out && fclose(out)) ok = 0;
	if (!ok) fprintf(stderr, "error: encryption failed\n");
	return ok;
}

int rsa_decrypt(const char *in_path, const char *out_path, const char *key_path)
{
	size_t n, exponent, encrypted, value; int ok = 0; FILE *in = NULL, *out = NULL;
	if (!read_key(key_path, &n, &exponent)) return 0;
	in = fopen(in_path, "rb");
	if (!in) { fprintf(stderr, "error: %s: %s\n", in_path, strerror(errno)); goto done; }
	out = fopen(out_path, "wb");
	if (!out) { fprintf(stderr, "error: %s: %s\n", out_path, strerror(errno)); goto done; }
	for (;;) {
		size_t got = fread(&encrypted, 1, sizeof encrypted, in);
		if (!got) break;
		if (got != sizeof encrypted) { fprintf(stderr, "error: truncated ciphertext\n"); goto done; }
		if (encrypted >= n) { fprintf(stderr, "error: ciphertext outside modulus\n"); goto done; }
		value = mod_power(encrypted, exponent, n);
		if (value > UCHAR_MAX || fputc((unsigned char)value, out) == EOF) {
			fprintf(stderr, "error: decrypted value is not a byte\n"); goto done;
		}
	}
	if (!ferror(in)) ok = 1;
done:
	if (in && fclose(in)) ok = 0;
	if (out && fclose(out)) ok = 0;
	if (!ok) fprintf(stderr, "error: decryption failed\n");
	return ok;
}
