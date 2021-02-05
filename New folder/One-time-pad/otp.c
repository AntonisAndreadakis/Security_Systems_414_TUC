#ifndef OATH_NO_TOTP
	#include <time.h>
#endif

#include <string.h> 		//memcpy, strlen
#include <stdint.h> 		//uint8_t, uint32_t, uint64_t
#include <openssl/sha.h>	//SHA1

/**
	Simple OTP token generator library, conforming to RFCs 4226 & 6238
	and compatible to Googles 2FA implementation.

	Updates at http://dev.cbcdn.com/	

	Resource credits
	----------------
		https://tools.ietf.org/html/rfc6238
		https://tools.ietf.org/html/rfc4226
		http://code.google.com/p/google-authenticator/
		http://www.deadhat.com/wlancrypto/hmac_sha1.c
		http://www.openssl.org/docs/crypto/sha.html
	
	Usage example
	-------------
		int main(){
			unsigned char buf[17]="M5XW6Z3MMVQXK5DI"; //base32 of "googleauth"	
			printf("%06d",oath_generate_totp(buf));
			return 0;
		}
	
	History
	-------
		21052013 0126 File creation date
		24052013 2355 TOTP functionality pass
		25052013 0239 Changed naming from gauth_* to oath_*
		25052013 0249 Added WTFPL, implemented HOTP
*/

/**
 DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
 Version 2, December 2004 

 Copyright (C) 2004 Sam Hocevar <sam@hocevar.net> 

 Everyone is permitted to copy and distribute verbatim or modified 
 copies of this license document, and changing it is allowed as long 
 as the name is changed. 
 
	DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE 
	TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION 

	0. You just DO WHAT THE FUCK YOU WANT TO.
*/


/**
	Expand this to (a) to have debug messages printed to stdout
*/
#define OATH_DEBUG(a)

/**
	The size (in bits) of a uint64_t
*/
#define U64TBITSIZE (sizeof(uint64_t)*8)

/**
	HMAC-SHA1 maximum parameter length
	Inner Pass: 64 Bytes inner padding + 8 Bytes data (timestamp)
	Outer Pass: 64 Bytes outer padding + 20 Bytes data (inner hash)
*/
#define OATH_HMACSHA1_MAXPARAMLEN (64+20)

/**
	Modulus. Ultimately decides the length of the auth token
*/
#define OATH_CODE_MODULUS 1000000

/**
	Padding length used for HMAC-SHA1 key
*/
#define OATH_HMACSHA1_PADLEN 64

uint32_t oath_char_index(unsigned char* haystack,unsigned char needle){
	uint32_t i;
	for(i=0;haystack[i]!='\0'&&haystack[i]!=needle;i++){
	}
	return (haystack[i]>0)?i:-1;
}

/**
	Destructively decode input as base32
	Returns length of decoded string (including padding)
*/
uint32_t oath_base32_decode(unsigned char* input){
	unsigned char dict[]="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	uint32_t seqs=0;
	size_t in_len=0;
	size_t current_pos=0;
	uint32_t current_seq=0;
	uint32_t i=0;
	uint64_t current_sequence=0;
	uint64_t current_char=0;
	
	in_len=strlen((char*)input);
	
	if((in_len%8)!=0){
		return 0;
	}
	
	seqs=in_len/8;
	
	for(current_seq=0;current_seq<seqs;current_seq++){
		//prepare current sequence
		current_sequence=0;
		
		//do transform & shift
		for(i=0;i<8;i++){
			current_char=(input[current_seq*8+i]=='=')?0:oath_char_index(dict,input[current_seq*8+i]);
			if(current_char==-1){
				return 0;
			}
			current_sequence|=(current_char<<(U64TBITSIZE-5*(i+1)));
		}
		
		for(i=0;i<5;i++){
			//move into input array at current_pos
			input[current_pos++]=(current_sequence&(((uint64_t)(0xFF))<<(U64TBITSIZE-8*(i+1))))>>(U64TBITSIZE-8*(i+1));
		}
		//terminate
		input[current_pos]=0;
	}
	return current_pos;
}

/**
	Calculate HMAC-SHA1 hash of a key and a integral message
	HMAC is implemented as SHA1([key xor 0x5c].SHA1([key xor 0x36].[8bytes integer big endian]))
	hash must be a buffer allocated by the caller to hold at least SHA_DIGEST_LENGTH bytes
*/
void oath_hmacsha1(uint8_t* key, uint32_t keylen, uint64_t counter, uint8_t* hash){
	uint8_t key_hash[SHA_DIGEST_LENGTH];
	uint8_t hash_data[OATH_HMACSHA1_MAXPARAMLEN];
	uint32_t i=0;
	
	if(keylen>64){
		OATH_DEBUG(printf("Key too long, hashing\n"));
		SHA1((unsigned char*)key,keylen,key_hash);
		key=key_hash;
		keylen=SHA_DIGEST_LENGTH;
	}
	
	//prepare inner pass
	OATH_DEBUG(printf("Preparing for first pass\n"));
	memset(hash_data,0x36,OATH_HMACSHA1_PADLEN);
	//insert key
	OATH_DEBUG(printf("XORing in %d bytes of key for first pass\n",keylen));
	for(i=0;i<keylen;i++){
		hash_data[i]^=key[i];
	}
	
	//insert data (8byte counter)
	OATH_DEBUG(printf("Inserting first pass data\n"));
	for(i=0;i<8;i++){
		hash_data[OATH_HMACSHA1_PADLEN+i]=(counter&(((uint64_t)(0xFF))<<(U64TBITSIZE-8*(i+1))))>>(U64TBITSIZE-8*(i+1));
	}
	
	//finish pass 1
	OATH_DEBUG(printf("Hashing first pass\n"));
	SHA1((unsigned char*)hash_data,OATH_HMACSHA1_PADLEN+8,hash);

	//prepare pass outer pass
	OATH_DEBUG(printf("Preparing for second pass\n"));
	memset(hash_data,0x5c,OATH_HMACSHA1_PADLEN);
	//insert key
	OATH_DEBUG(printf("XORing in %d bytes of key for second pass\n",keylen));
	for(i=0;i<keylen;i++){
		hash_data[i]^=key[i];
	}
	//insert data
	OATH_DEBUG(printf("Inserting second pass data\n"));
	memcpy(hash_data+OATH_HMACSHA1_PADLEN,hash,SHA_DIGEST_LENGTH);
	//finish pass 2
	OATH_DEBUG(printf("Hashing second pass\n"));
	SHA1((unsigned char*)hash_data,OATH_HMACSHA1_PADLEN+SHA_DIGEST_LENGTH,hash);
}

/**
	Generate HOTP authenthication token from
	a base32'd secret input string
	
	Input is modified in the process
	
	Returns -1 on failure
*/
uint32_t oath_generate_hotp(unsigned char* secret, uint64_t counter){
	uint8_t offset;
	uint32_t code=0;
	uint32_t keylen;
	uint8_t hash[SHA_DIGEST_LENGTH];

	keylen=oath_base32_decode(secret);
	if(keylen<1){
		return -1;
	}
	
	OATH_DEBUG(printf("Input base32 has decoded length %d\n",keylen));
  
	oath_hmacsha1(secret,keylen,counter,hash);

	offset=hash[19]&0xF;
	OATH_DEBUG(printf("Using offset %d\n",offset));
	
	code=((hash[offset]&0x7F)<<24) | ((hash[offset+1])<<16) | ((hash[offset+2])<<8) | ((hash[offset+3]));
	
	return code%OATH_CODE_MODULUS;
}

#ifndef OATH_NO_TOTP
/**
	Generate TOTP authenthication token from
	a base32'd secret input string
	
	Input is modified in the process
	
	Returns -1 on failure
*/
uint32_t oath_generate_totp(unsigned char* secret){
	uint64_t current_time;
	current_time=time(NULL)/30;
	if(current_time==-1){
		return -1;
	}
	return oath_generate_hotp(secret,current_time);
}
#endif