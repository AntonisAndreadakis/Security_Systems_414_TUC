Greeter: Greeter.c
	gcc -ansi -static -fno-stack-protector -z execstack -g -no-pie -m32 Greeter.c -o Greeter
exploit:
	python2 shell.py > adsfg.txt
	(cat adsfg.txt ;cat)| ./Greeter
clean:
	rm -rf Greeter adsfg.txt
