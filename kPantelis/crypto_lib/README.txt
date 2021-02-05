Code developed under HPY417 - Systems and Information Security, ECE TUC 2020-21 Winter Sem.


	Konstantinos Pantelis -   	LAB41446433
	2015030070
	Undergrad. Student@ECE TUC
	github.com/dasApfel [code will be under "securious-tuc" project]
	

									** BASICS **

- All function and constant declarations are held under "simple_crypto.h".
- The implementation of the afforementioned functions can be found in "simple_crypto.c".
- A demo of use concerning the implementation can be found in "demo.c".
- Source code developed in Unbuntu Linux 19.10 [x86-64 architecture].
- All functions have extensive commenting either on declaration ".h" or in implementation file ".c"
- If questions about any technique arrise, github or kpantelis@isc.tuc.gr can be used for communicating.

				** ALGORITHMS - TECHNIQUES USED [Minor utility functions will not be analyzed] **

INPUT:

- Reading user's input takes place via calling <char *readInput()> which allocates compile and runtime memory resources to achieve its purpose [read input until <newline> or <EOF>].
- Input is then sanitized/ "cleaned out" from illegal characters (anything other than [0-9A-Za-z]) via 
<char *formatInput(char *)> .

KEY:

- In the event where a random key/entropy is needed, <char *generateKey(int n)> is called, which then creates a random key based on entropy collector "/dev/urandom" which is accesed byte-wise in order to prevent deadlocks in the actual system from happening. Under the assumption that urandom library uses the noise generated from peripherals as entropy seed this results to a "good in terms of randomness" ready to be used in <char *> format.

- When not certains whether about a string (mostly key or ciphertext) contains non-printable ASCII characters or not   <void printHex(char *)> is used. The afforementioned prints the HEX equivalent of the char in respective offset when parsing the string (a good example exists in "simple_crypto.c"). 

ONE TIME PAD:

- Encryption via a byte-wise parse between plaintext and key in <char *>/string format and then an XOR among the respective ASCII digits happening via <char *encryptOTP(char *, char *)>.

- Decryption follows same rule but by reversing the XOR's operands.

- Extensive comments upon implemantation can be found in "simple_crypto.c"

CEASAR:

- Can be implemented via either modulo sums or adjacent matrices technique (well known when mathematical problems need to be expressed in source code). Eitherway mine is implemented via an adjacent matrix.

- Adjacent matrix initialised in <poolInit()> containig a "line" of the valid alphabet ([0-9A-Za-z]).
- Encoding takes place via addition of adjacent indexes, shifting by <int key> and modulo arithmetic (to adjust in the desired space).

- Decoding is identical operation but with a reversed order.

- Builded and tested for keys in range =  [0, 66251] (non-negative ones), input validation DOES take place.

- See <char *encryptCeasar(char *, int k)>, <char *decryptCeasar(char *, int k)>.

VIGENERE:

- Also can easily be implemented via both adjacent matrices (2 - dimensional since its a 2-d CEASAR) and modulo sums. Modulo sums techinique has been chosen just to increase diversity in the code :D . 

- Bare in mind that <char *key> might need expansion therefore check the <char *extendKey(char *, char *)>.

- Builded and tested for [A-Z] space (both input and ciphertext), no validation made.

- See <char *encryptVigenere(char *, int k)>, <char *decryptVigenere(char *, int k)>, 
	<char *extendKey(char *, char *).



								** COMPILATION  -  TESTING AND OTHERS. **

-Type "make all" to compile.
-Type "make clean" to clean the build.
-Type "meake test" to compile and then run "./demo" executable.


								** LICENSE **
- Common MIT license .


							** WARNINGS **

- These forms of encryption even if secure (mostly OTP) are not unbreakable therefore cannot be thought as a "secure way of comms" or a "secure comms line".

- Strong suggestion when running above: USE A LINUX BASED MACHINE.

