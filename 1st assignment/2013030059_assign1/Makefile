CC ?= gcc
AR ?= ar
CPPFLAGS ?= -D_POSIX_C_SOURCE=200809L
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
LDFLAGS ?=
ARFLAGS = rcs

.PHONY: all check sanitize clean

all: demo

libsimple_crypto.a: simple_crypto.o
	$(AR) $(ARFLAGS) $@ $^

simple_crypto.o: simple_crypto.c simple_crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

demo.o: demo.c simple_crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

demo: demo.o libsimple_crypto.a
	$(CC) $(LDFLAGS) -o $@ demo.o libsimple_crypto.a

test_simple_crypto.o: test_simple_crypto.c simple_crypto.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<

test_simple_crypto: test_simple_crypto.o libsimple_crypto.a
	$(CC) $(LDFLAGS) -o $@ test_simple_crypto.o libsimple_crypto.a

check: test_simple_crypto demo
	./test_simple_crypto
	printf 'secret\nhello\n4\nATTACKATDAWN\nLEMON\n' | ./demo > demo-output.tmp
	grep -Eq '^\[OTP\] encrypted: [0-9a-f]{12}$$' demo-output.tmp
	grep -Fx '[OTP] decrypted: secret' demo-output.tmp
	grep -Fx '[Caesars] encrypted: lipps' demo-output.tmp
	grep -Fx '[Caesars] decrypted: hello' demo-output.tmp
	grep -Fx '[Vigenere] encrypted: LXFOPVEFRNHR' demo-output.tmp
	grep -Fx '[Vigenere] decrypted: ATTACKATDAWN' demo-output.tmp
	rm -f demo-output.tmp

sanitize: clean
	$(MAKE) CFLAGS='$(CFLAGS) -O1 -fsanitize=address,undefined -fno-omit-frame-pointer' \
	        LDFLAGS='-fsanitize=address,undefined' check

clean:
	rm -f demo test_simple_crypto libsimple_crypto.a *.o demo-output.tmp
