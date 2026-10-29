CC ?= cc
CFLAGS ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Werror
.PHONY: all check clean
all: monitor

monitor: monitor.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) monitor.c -o monitor -lpcap

check: monitor
	python3 test_monitor.py

clean:
	rm -f monitor
