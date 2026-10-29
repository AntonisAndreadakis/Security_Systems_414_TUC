#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#define AES_BLOCK_SIZE 16U
#define CMAC_SIZE 16U
#define MAX_KEY_SIZE 32U

enum operation {
    OP_NONE = 0,
    OP_DECRYPT,
    OP_ENCRYPT,
    OP_SIGN,
    OP_VERIFY
};

static void usage(FILE *stream, const char *program)
{
    fprintf(stream,
            "Usage:\n"
            "  %s -i INPUT -o OUTPUT -p PASSWORD -b {128|256} {-d|-e|-s|-v}\n"
            "  %s -h\n\n"
            "Options:\n"
            "  -i path   input file\n"
            "  -o path   output file\n"
            "  -p text   password used for key derivation\n"
            "  -b bits   AES key size: 128 or 256\n"
            "  -d        decrypt\n"
            "  -e        encrypt\n"
            "  -s        encrypt and append a plaintext CMAC\n"
            "  -v        decrypt and verify an appended CMAC\n"
            "  -h        show this help\n",
            program, program);
}

static const EVP_CIPHER *cipher_for_bits(int bits)
{
    return bits == 128 ? EVP_aes_128_ecb() : EVP_aes_256_ecb();
}

static const char *cmac_cipher_name_for_bits(int bits)
{
    /* OpenSSL CMAC requires the CBC form of the underlying block cipher. */
    return bits == 128 ? "AES-128-CBC" : "AES-256-CBC";
}

static int parse_bits(const char *text, int *bits)
{
    char *end = NULL;
    long value;

    errno = 0;
    value = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' ||
        (value != 128 && value != 256)) {
        return 0;
    }
    *bits = (int)value;
    return 1;
}

static int read_file(const char *path, unsigned char **data, size_t *length)
{
    FILE *file = NULL;
    long file_size;
    unsigned char *buffer = NULL;
    size_t bytes_read;

    file = fopen(path, "rb");
    if (file == NULL) {
        fprintf(stderr, "Error: cannot open input '%s': %s\n", path,
                strerror(errno));
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (file_size = ftell(file)) < 0 ||
        fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Error: cannot determine size of '%s'.\n", path);
        fclose(file);
        return 0;
    }
    if ((unsigned long)file_size > (unsigned long)(INT_MAX - EVP_MAX_BLOCK_LENGTH)) {
        fprintf(stderr, "Error: input is too large for the OpenSSL EVP API.\n");
        fclose(file);
        return 0;
    }

    buffer = malloc(file_size == 0 ? 1U : (size_t)file_size);
    if (buffer == NULL) {
        fprintf(stderr, "Error: out of memory while reading input.\n");
        fclose(file);
        return 0;
    }
    bytes_read = fread(buffer, 1U, (size_t)file_size, file);
    if (bytes_read != (size_t)file_size || ferror(file)) {
        fprintf(stderr, "Error: failed to read all bytes from '%s'.\n", path);
        OPENSSL_cleanse(buffer, file_size == 0 ? 1U : (size_t)file_size);
        free(buffer);
        fclose(file);
        return 0;
    }
    if (fclose(file) != 0) {
        fprintf(stderr, "Error: failed to close input '%s'.\n", path);
        OPENSSL_cleanse(buffer, file_size == 0 ? 1U : (size_t)file_size);
        free(buffer);
        return 0;
    }

    *data = buffer;
    *length = bytes_read;
    return 1;
}

static int write_file(const char *path, const unsigned char *data, size_t length)
{
    FILE *file = fopen(path, "wb");

    if (file == NULL) {
        fprintf(stderr, "Error: cannot open output '%s': %s\n", path,
                strerror(errno));
        return 0;
    }
    if (length != 0U && fwrite(data, 1U, length, file) != length) {
        fprintf(stderr, "Error: failed to write all bytes to '%s'.\n", path);
        fclose(file);
        return 0;
    }
    if (fclose(file) != 0) {
        fprintf(stderr, "Error: failed to close output '%s'.\n", path);
        return 0;
    }
    return 1;
}

static int derive_key(const char *password, int bits, unsigned char *key)
{
    unsigned char unused_iv[EVP_MAX_IV_LENGTH] = {0};
    int derived;

    derived = EVP_BytesToKey(cipher_for_bits(bits), EVP_sha1(), NULL,
                             (const unsigned char *)password,
                             (int)strlen(password), 1, key, unused_iv);
    OPENSSL_cleanse(unused_iv, sizeof(unused_iv));
    if (derived != bits / 8) {
        fprintf(stderr, "Error: key derivation failed.\n");
        return 0;
    }
    return 1;
}

static int encrypt_data(const unsigned char *input, size_t input_length,
                        const unsigned char *key, int bits,
                        unsigned char **output, size_t *output_length)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char *buffer = NULL;
    int first_length = 0;
    int final_length = 0;
    int ok = 0;

    context = EVP_CIPHER_CTX_new();
    buffer = malloc(input_length + EVP_MAX_BLOCK_LENGTH);
    if (context == NULL || buffer == NULL) {
        fprintf(stderr, "Error: cannot allocate encryption state.\n");
        goto done;
    }
    if (EVP_EncryptInit_ex(context, cipher_for_bits(bits), NULL, key, NULL) != 1 ||
        EVP_EncryptUpdate(context, buffer, &first_length, input,
                          (int)input_length) != 1 ||
        EVP_EncryptFinal_ex(context, buffer + first_length, &final_length) != 1) {
        fprintf(stderr, "Error: encryption failed.\n");
        goto done;
    }

    *output = buffer;
    *output_length = (size_t)first_length + (size_t)final_length;
    buffer = NULL;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(context);
    if (buffer != NULL) {
        OPENSSL_cleanse(buffer, input_length + EVP_MAX_BLOCK_LENGTH);
        free(buffer);
    }
    return ok;
}

static int decrypt_data(const unsigned char *input, size_t input_length,
                        const unsigned char *key, int bits,
                        unsigned char **output, size_t *output_length)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char *buffer = NULL;
    int first_length = 0;
    int final_length = 0;
    int ok = 0;

    if (input_length == 0U || input_length % AES_BLOCK_SIZE != 0U) {
        fprintf(stderr, "Error: ciphertext length must be a non-zero multiple of 16.\n");
        return 0;
    }

    context = EVP_CIPHER_CTX_new();
    buffer = malloc(input_length);
    if (context == NULL || buffer == NULL) {
        fprintf(stderr, "Error: cannot allocate decryption state.\n");
        goto done;
    }
    if (EVP_DecryptInit_ex(context, cipher_for_bits(bits), NULL, key, NULL) != 1 ||
        EVP_DecryptUpdate(context, buffer, &first_length, input,
                          (int)input_length) != 1 ||
        EVP_DecryptFinal_ex(context, buffer + first_length, &final_length) != 1) {
        fprintf(stderr, "Error: decryption failed (wrong key or corrupted ciphertext).\n");
        goto done;
    }

    *output = buffer;
    *output_length = (size_t)first_length + (size_t)final_length;
    buffer = NULL;
    ok = 1;

done:
    EVP_CIPHER_CTX_free(context);
    if (buffer != NULL) {
        OPENSSL_cleanse(buffer, input_length);
        free(buffer);
    }
    return ok;
}

static int generate_cmac(const unsigned char *data, size_t data_length,
                         const unsigned char *key, int bits,
                         unsigned char tag[CMAC_SIZE])
{
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *context = NULL;
    OSSL_PARAM parameters[2];
    char cipher_name[16];
    size_t tag_length = 0;
    int ok = 0;

    if (snprintf(cipher_name, sizeof(cipher_name), "%s",
                 cmac_cipher_name_for_bits(bits)) < 0) {
        return 0;
    }
    parameters[0] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_CIPHER, cipher_name, 0);
    parameters[1] = OSSL_PARAM_construct_end();

    mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (mac != NULL) {
        context = EVP_MAC_CTX_new(mac);
    }
    if (context == NULL ||
        EVP_MAC_init(context, key, (size_t)(bits / 8), parameters) != 1 ||
        EVP_MAC_update(context, data, data_length) != 1 ||
        EVP_MAC_final(context, tag, &tag_length, CMAC_SIZE) != 1 ||
        tag_length != CMAC_SIZE) {
        fprintf(stderr, "Error: CMAC generation failed.\n");
        goto done;
    }
    ok = 1;

done:
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(mac);
    return ok;
}

int main(int argc, char **argv)
{
    const char *input_path = NULL;
    const char *output_path = NULL;
    const char *password = NULL;
    int bits = 0;
    enum operation operation = OP_NONE;
    int operation_count = 0;
    int option;
    int status = EXIT_FAILURE;
    unsigned char key[MAX_KEY_SIZE] = {0};
    unsigned char tag[CMAC_SIZE] = {0};
    unsigned char expected_tag[CMAC_SIZE] = {0};
    unsigned char *input = NULL;
    unsigned char *result = NULL;
    unsigned char *ciphertext = NULL;
    size_t input_length = 0;
    size_t result_length = 0;
    size_t ciphertext_length = 0;

    opterr = 0;
    while ((option = getopt(argc, argv, "hi:o:p:b:desv")) != -1) {
        switch (option) {
        case 'h':
            usage(stdout, argv[0]);
            return EXIT_SUCCESS;
        case 'i':
            if (input_path != NULL) {
                fprintf(stderr, "Error: -i may be specified only once.\n");
                goto cleanup;
            }
            input_path = optarg;
            break;
        case 'o':
            if (output_path != NULL) {
                fprintf(stderr, "Error: -o may be specified only once.\n");
                goto cleanup;
            }
            output_path = optarg;
            break;
        case 'p':
            if (password != NULL) {
                fprintf(stderr, "Error: -p may be specified only once.\n");
                goto cleanup;
            }
            password = optarg;
            break;
        case 'b':
            if (bits != 0 || !parse_bits(optarg, &bits)) {
                fprintf(stderr, "Error: -b must be specified once as 128 or 256.\n");
                goto cleanup;
            }
            break;
        case 'd':
            operation = OP_DECRYPT;
            operation_count++;
            break;
        case 'e':
            operation = OP_ENCRYPT;
            operation_count++;
            break;
        case 's':
            operation = OP_SIGN;
            operation_count++;
            break;
        case 'v':
            operation = OP_VERIFY;
            operation_count++;
            break;
        default:
            fprintf(stderr, "Error: unknown or incomplete option.\n");
            goto cleanup;
        }
    }

    if (optind != argc || input_path == NULL || *input_path == '\0' ||
        output_path == NULL || *output_path == '\0' ||
        password == NULL || *password == '\0' || bits == 0 ||
        operation_count != 1) {
        fprintf(stderr, "Error: all required options and exactly one operation are needed.\n");
        usage(stderr, argv[0]);
        goto cleanup;
    }
    if (!read_file(input_path, &input, &input_length) ||
        !derive_key(password, bits, key)) {
        goto cleanup;
    }

    switch (operation) {
    case OP_ENCRYPT:
        if (!encrypt_data(input, input_length, key, bits,
                          &result, &result_length) ||
            !write_file(output_path, result, result_length)) {
            goto cleanup;
        }
        break;

    case OP_DECRYPT:
        if (!decrypt_data(input, input_length, key, bits,
                          &result, &result_length) ||
            !write_file(output_path, result, result_length)) {
            goto cleanup;
        }
        break;

    case OP_SIGN:
        if (!generate_cmac(input, input_length, key, bits, tag) ||
            !encrypt_data(input, input_length, key, bits,
                          &ciphertext, &ciphertext_length)) {
            goto cleanup;
        }
        if (ciphertext_length > SIZE_MAX - CMAC_SIZE) {
            fprintf(stderr, "Error: signed output is too large.\n");
            goto cleanup;
        }
        result_length = ciphertext_length + CMAC_SIZE;
        result = malloc(result_length);
        if (result == NULL) {
            fprintf(stderr, "Error: cannot allocate signed output.\n");
            goto cleanup;
        }
        memcpy(result, ciphertext, ciphertext_length);
        memcpy(result + ciphertext_length, tag, CMAC_SIZE);
        if (!write_file(output_path, result, result_length)) {
            goto cleanup;
        }
        break;

    case OP_VERIFY:
        if (input_length < AES_BLOCK_SIZE + CMAC_SIZE ||
            (input_length - CMAC_SIZE) % AES_BLOCK_SIZE != 0U) {
            fprintf(stderr, "Verification failed: invalid signed input length.\n");
            status = 2;
            goto cleanup;
        }
        ciphertext_length = input_length - CMAC_SIZE;
        memcpy(expected_tag, input + ciphertext_length, CMAC_SIZE);
        if (!decrypt_data(input, ciphertext_length, key, bits,
                          &result, &result_length) ||
            !generate_cmac(result, result_length, key, bits, tag) ||
            CRYPTO_memcmp(tag, expected_tag, CMAC_SIZE) != 0) {
            fprintf(stderr, "Verification failed.\n");
            status = 2;
            goto cleanup;
        }
        if (!write_file(output_path, result, result_length)) {
            goto cleanup;
        }
        puts("Verified.");
        break;

    case OP_NONE:
        goto cleanup;
    }

    status = EXIT_SUCCESS;

cleanup:
    OPENSSL_cleanse(key, sizeof(key));
    OPENSSL_cleanse(tag, sizeof(tag));
    OPENSSL_cleanse(expected_tag, sizeof(expected_tag));
    if (input != NULL) {
        OPENSSL_cleanse(input, input_length == 0U ? 1U : input_length);
        free(input);
    }
    if (result != NULL) {
        OPENSSL_cleanse(result, result_length == 0U ? 1U : result_length);
        free(result);
    }
    if (ciphertext != NULL) {
        OPENSSL_cleanse(ciphertext, ciphertext_length);
        free(ciphertext);
    }
    return status;
}
