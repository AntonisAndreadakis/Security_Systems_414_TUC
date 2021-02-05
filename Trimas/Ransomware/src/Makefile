all: logger acmonitor test_aclog test

test: file_creation.c
	gcc file_creation.c -o file

logger: logger.c
	gcc -Wall -std=c99 -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog
	
clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm file_logging.log
	rm file
	rm -rf decrypted/*
	rmdir decrypted
	sudo rm file_0 file_1 file_2 file_3 file_4 file_5 file_6 file_7 file_8 file_9

