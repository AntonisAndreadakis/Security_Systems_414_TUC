CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
LDLIBS += -lcrypto

TARGET := assign_1
SOURCE := assign_1.c

.PHONY: all clean check

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDLIBS)

check: $(TARGET)
	sh tests/test.sh

clean:
	rm -f $(TARGET)
