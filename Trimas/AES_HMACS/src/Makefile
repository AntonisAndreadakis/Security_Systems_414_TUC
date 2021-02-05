CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
LIBSSL = -lssl -lcrypto

TARGETS = assign_1


all: $(TARGETS)

assign_1: assign_1.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

test:
	bash run_tests.sh

delete:
	rm decryptme_256.txt hpy414_encryptme_128.txt verifyme_128.txt hpy414_signme_256.txt hpy414_signme_128.txt
	rm encryptme_256_out.txt hpy414_decryptme_128_out.txt signme_128_out.txt hpy414_verifyme_256_out.txt hpy414_verifyme_128_out.txt

clean:
	rm -f $(TARGETS)
