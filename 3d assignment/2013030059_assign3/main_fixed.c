#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "rsa_fixed.h"

static void usage(FILE *f)
{
	fprintf(f, "Usage:\n  assign_3 -g\n  assign_3 -i INPUT -o OUTPUT -k KEY [-e|-d]\n  assign_3 -h\n");
}

int main(int argc, char **argv)
{
	int opt, mode = -1;
	const char *in = NULL, *out = NULL, *key = NULL;
	while ((opt = getopt(argc, argv, "i:o:k:degh")) != -1) {
		switch (opt) {
		case 'i': in = optarg; break;
		case 'o': out = optarg; break;
		case 'k': key = optarg; break;
		case 'd': case 'e': case 'g': {
			int next = opt == 'd' ? 0 : opt == 'e' ? 1 : 2;
			if (mode != -1 && mode != next) {
				fprintf(stderr, "error: choose exactly one mode\n");
				return EXIT_FAILURE;
			}
			mode = next; break;
		}
		case 'h': usage(stdout); return EXIT_SUCCESS;
		default: usage(stderr); return EXIT_FAILURE;
		}
	}
	if (optind != argc || mode < 0 || (mode != 2 && (!in || !out || !key)) ||
	    (mode == 2 && (in || out || key))) {
		usage(stderr); return EXIT_FAILURE;
	}
	if (mode == 2) return rsa_keygen() ? 0 : 1;
	if (mode == 1) return rsa_encrypt(in, out, key) ? 0 : 1;
	return rsa_decrypt(in, out, key) ? 0 : 1;
}
