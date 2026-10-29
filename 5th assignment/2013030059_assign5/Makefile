.PHONY: all check clean clear

all: logger acmonitor test_aclog

check:
	python3 assignment.py --self-test

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl -lssl

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

clean:
	rm -f logger.so test_aclog acmonitor

clear:
	@echo "Refusing to truncate fixture files; use a disposable directory instead."
	@false
