In this first assignment, we implement 3 algorithms for encryption and decryption. Our implementation is in
C programming language on lunix-unix based systems.
	1) 	Our first algorithm is One-Time-Pad. Takes as a parameter a passphrase. Using a key
		as long as the passhphrase, by calling "/dev/urandom", we combine our passphrase with
		it (XOR) and we get the encrypted message. Same is done for decryption.

	2)	Caesar's cipher: This algorithm uses one more parameter. The key is not made by any
		function. Each letter of the passphrase is shifted to the right by "key" positions.
		Reverse method is followed for decryption (shift to the left).
	Both algorithms use an alphabet which consists of numbers 0-9 or letters (lower or uppercase).

	3)	Last algorithm named Vigenere's cipher, is similar to above (Caesar's). There is one
		difference. User is not asked to provide a number as key for encryption, but a passphrase
		with length equal to our plaintext. This purpose is to "match" each letter of the
		plaintext to the passphrase-key and shift it right. For decryption we shift left, so
		we follow reverse method. 
	One main difference with the above algorithms is the fact we use a specific alphabet. Only uppercase
	letters A-Z.
	In my implementation, we can use lower and our encrypted-decrypted message is provided in uppercase.

So, there are 2 programms. One is simple_crypto.c and includes all the algorithms and the other is demo.c
that uses simple_crypto.c and is executed in order to ask input from user.
The simple_crypto.h is the library and describes the above programms.
At last, we have a Makefile to compile our programms.
