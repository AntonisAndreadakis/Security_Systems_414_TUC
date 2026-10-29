CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic

.PHONY: all check clean clear

all: logger.so acmonitor test_aclog

# The Python port is the maintained entry point; this also builds and
# smoke-tests the legacy C/Bash deliverables the assignment brief asks for
# (logger.c, acmonitor.c, ransomware.sh), entirely inside a disposable
# temporary directory (see tests/check_legacy.sh).
check: all
	sh tests/check_legacy.sh
	python3 assignment.py --self-test

logger.so: logger.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -lcrypto -ldl

acmonitor: acmonitor.c
	$(CC) $(CFLAGS) -o $@ $<

test_aclog: test_aclog.c
	$(CC) $(CFLAGS) -o $@ $<

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -f logger.so acmonitor test_aclog
	rm -rf ./aclog-test

clear:
	@echo "Refusing to truncate fixture files; use a disposable directory instead."
	@false
