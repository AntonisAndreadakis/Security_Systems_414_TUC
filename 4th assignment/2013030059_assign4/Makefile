CC ?= gcc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic

.PHONY: all run clean clear check

all: logger.so acmonitor test_aclog

logger.so: logger.c
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $< -lcrypto -ldl

acmonitor: acmonitor.c
	$(CC) $(CFLAGS) -o $@ $<

test_aclog: test_aclog.c
	$(CC) $(CFLAGS) -o $@ $<

run: logger.so test_aclog
	ACLOG_PATH=./file_logging.log LD_PRELOAD=./logger.so ./test_aclog

check: all
	python3 test_safe.py

clean:
	rm -f logger.so test_aclog acmonitor
	rm -f ./aclog-test/denied-*.txt ./aclog-test/modified.txt
	rmdir ./aclog-test 2>/dev/null || true

clear:
	: > file_logging.log
