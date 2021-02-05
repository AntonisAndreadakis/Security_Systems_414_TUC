#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>
#include<score.h>
/**
Thi is an example of substitution cipher where letters are shifted by a key between 3 and 26. A key greter than 0 is advisable.

The alphabet can be shifted up to 25 places, but shifting a letter 26 places takes it back to its original position, and shifting it 27 places is the same as shifting it 1 place. So there are 25 keys.

Reference:http://www.simonsingh.net/The_Black_Chamber/caesar.html
*/
const char CAESAR[]={'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};

char * decrypt_caesar(char crypt[],int key){
	int A=(int)('A');
	int Z=(int)('Z');
	printf("R: %s=>%zd\n",crypt,strlen(crypt));
	char *text=(char*)malloc(strlen(crypt));
	int i;
	int c;
	for(i=0;i<strlen(crypt);i++){
		c=toupper(crypt[i])-(key);
		if(c<A){ //Round to the begining
			text[i]=(char)((Z-(A-c))+1);
		}else{
			text[i]=(char)(c);
		}
	}
	return text;
}

int main(int argc,char*argv[]){
	char text[]="Hello there an A and a Z XYZ";
	int key=3;
	char *crypt=encrypt_caesar(text,key);
	printf("Plain Text:%s\n",text);
	printf("Encrypted:%s\n",crypt);
	char *decrypt=decrypt_caesar(crypt,key);
	printf("Descrypted:%s\n",decrypt);
}
