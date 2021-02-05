Andreadakis Antonios - 2013030059 - LAB41446117


## Description:
	Buffer Overflow exploitation. In this assignment, we try to exploit a buffer overflow vulnerability in a very simple and badly written program in C.
	The program is named `Greeter`, it asks for your name and greets you. Using function `readString` and `gets` in order to place the name of user in a
	local buffer, copying the local in a global buffer and returning, the developer does not check if the size of the input string is larger than buffer's
	size. Given this situation, a user with malicious intent is able to provide specially crafted input that will overwrite the return address of `readString`
	and divert the execution anywhere in the `Greeter` program. I created a simple script for our purpose of the exploit, using a premade shellcode found
	online. After the creation of `myRes.txt`, I run the Greeter (see below how to run) and the exploit does the job and return a terminal within the program.
	In order to test it, run `ls` or any other command and the files of the folder will be listed.


## Modes:
	Make sure you have installed the gcc-multilib package:	sudo apt-get install gcc-multilib. This helps in compilation on different architecture OS.
	A very important thing, is to run in python2 version our exploit (see below). We do not need to type python2 as it is default version, so
	`python 'something'` is fine.


## Running:
	python exploit.py > myRes.txt	->	create our injection and store it on a txt file
	(cat myRes.txt ;cat)| ./Greeter	->	run `Greeter` through my txt file (so attack on target)
	ls / whoami (etc)		->	terminal never returns to previous (hit ctrl+z or ctrl+c), so we are done!


## Notes:

	>	I did not re-compile Greeter.c as there was no need to.

	>	I did not modify ASLR as there was no need to.

	>	I tried to run at GDB, a string 'abcdefghijklmnopqrstuvwxyz0123456789' as input name and program accepted the string as correct until '5', so last part '6789'
	        was dumped, and no error was found. Then, I tried string 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ' and there was a segmentation fault
	        on the following address:
	        \000\000\000ABCDEFGHIJKLMNOPQRSTUVWXYZ\000\000Ϗ\004\b\037\342\006\b\000\220\r\b\000\220\r\bϏ\004\b\001\000\000\000\004\321\377\377\f\321\377\377\244\320\377\377.
	        Again the string seems to be correctly accepted until '5' (which is suitable for buffer's length = 32) and then crashes. This is common sense, because there is
	        no check for user's input (if it is in a valid range for our buffer).
	        I tried option 'print Name' (as 'Name' is the variable of the input) and it's address was '\000'. This means, we have issue on variable 'Name' as it returns.
	
	>	Running the command `x/xw $esp` (while gdb is opened), I found the return address of variable 'Name' as `0xffffd030`, which represents the address of our buffer.
	        But it keeps changing. So some advanced search (using `disas main` ) gives us the desired address `0x80dacc0` which is the true return address. This can be
	        explained better, if running `disas readString` and observe the fact that after readString call, our %ebp has offset 0x2c (so our buffer is never 32 bytes) and
	        with this, we understand that our %ebp is 42 (or 44) 'positions' right. As it is known from previous knowledge, the static & dynamic pointers always have 'bigger' length.
	
	>	The shell code I used: dhavalkapil.com/blogs/Shellcode-Injection/?fbclid=IwAR3GsXzgZ9XUdrVmSO6AHuGSEuuRwYpuOVkVeK-vcDWIYcq9LVzxwMOoRjo

	>	In my zip there you find the following files:
						- Greeter.c (nothing changed from the default)
						- Greeter (made from Greeter.c, also not changed)
						- Makefile (for the above)
						- exploit.py (my python file for our purpose)
						- myRes.txt (has the payload created from exploit.py)
						- Readme.md (of course, describing what I have done)
