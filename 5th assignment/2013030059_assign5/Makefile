all: logger acmonitor test_aclog

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl -lssl

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
	rm -rf file0.txt file1.txt file2.txt file3.txt file4.txt file5.txt file6.txt file7.txt file8.txt file9.txt
#	rm -rf test.txt test1.txt test2.txt test3.txt

clear:
	#>file_logging.log
	>file0.txt
	>file1.txt
	>file2.txt
	>file3.txt
	>file4.txt
	>file5.txt
	>file6.txt
	>file7.txt
	>file8.txt
	>file9.txt

