## Description:

Purpose of this assignment is to generate a symmetric encryption tool, written in C.
It provides AES encryption/decryption and CMAC signing/verifying functionality using the EVP API from OpenSSl toolkit.

## Modes:

`encrypt`
	-User provides a mode(128/256) in order to encrypt a specific plaintext,
	using also a key derived from the provided password.
	-EVP_EncryptFinal_ex handles the encryption and padding of the final data.
	-The encrypted message is saved.

`decrypt`
	-User provides a mode(128/256) in order to decrypt a specific plaintext,
	using also a key derived from the provided password.
	-EVP_EncryptFinal_ex handles the the final data.
	-The decrypted message is saved.

`sign`
	-User provides a mode(128/256) in order give an authentication code to a
	specific plaintext, using a key derived from the provided password.
	-Plaintext gets encrypted.
	-The authentication code is attached at the tail of the plaintext.
	-Whole message is stored in a file.

`verify`
	-Disassembles the authentication code and ciphertext from message.
	-Decrypts the ciphertext.
	-Generates new authentication code for the decrypted ciphertext.
	-Compares the 2 generated CMAC's and returns TRUE or FALSE.

`debug`
	I also provide a debug mode, simply adding '1' at the end of the command, to enable debuging.

## Example:

example:	./assign_1 -i input_filename.txt -o output_filename.txt -p password -b bits -e(for enable) 1
	We can also try -d for decryption or -s for signing or -v for verification, as described in
	help menu.

