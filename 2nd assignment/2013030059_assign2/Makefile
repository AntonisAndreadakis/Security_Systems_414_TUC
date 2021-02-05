CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
LIBSSL = -lssl -lcrypto
LDFLAGS = -L/usr/local/opt/openssl/lib
CPPFLAGS= -I/usr/local/opt/openssl/include

TARGETS = assign_1

UNAME_S := $(shell uname -s)
	ifeq ($(UNAME_S),Darwin)
		CCFLAGS += $(LDFLAGS)
		CCFLAGS +=$(CPPFLAGS)
	endif

all: $(TARGETS)

assign_1: assign_1.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

clean:
	rm -f $(TARGETS)
