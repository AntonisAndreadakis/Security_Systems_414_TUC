CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror -fstack-protector-strong
.PHONY: all check clean Greeter
all: greeter_safe
greeter_safe: greeter_safe.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $<
check: greeter_safe
	python3 test_safe.py
Greeter:
	@echo 'Original vulnerable lab build is outside the approved safe workflow.' >&2
	@exit 1
clean:
	rm -f greeter_safe
