#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#define MAX 100
int menu();
int encrypt();
int decrypt();
int cleaner();
int whatiscrypt();
int file_operation();
char dec_mes[100];
int main()
{
	menu();
	return 0;
}

int menu()								//Menu
{
	int choice;
	char choice2,choice3;
	printf("\n\n\t\t\tA Basic Cryptography Program\n");
	printf("\t\t\t____________________________\n");
	printf("\t\t\t\t\t\t\tBy Nihal\n");
	printf("1) Encryption\n");
	printf("2) Decryption\n");
	printf("3) But what is cryptography?\n");
	printf("4) Exit\n");
	printf("\nWhat you want to do? ");
	scanf("%d",&choice);
	getchar();
	if(choice==1)
	encrypt();
	else if(choice==2)
	decrypt();
	else if(choice==3)
	whatiscrypt();
	else if(choice==4)
	exit(0);
	else
	printf("\nNice Shot");
	printf("\nDo you want to clear this messy screen? (Y/N)");
	scanf("%c",&choice2);
	getchar();
	if((choice2=='Y') || (choice2=='y'))
	cleaner();
	printf("\nDo you want to play this game again? (Y/N)");
	scanf("%c",&choice3);
	getchar();
	if((choice3=='Y') || (choice3=='y'))
	menu();
	else if((choice3=='N') || (choice3=='n'))
	printf("\nHave a good day\n");
	else
	printf("\nDon't test my code\n");
	return 0;
}

int encrypt()								//Data Encryption
{
	char enc_mes[100];
	int i;
	printf("\nEnter your message that you want to encrypt:- ");
	fgets(enc_mes,MAX,stdin);
	printf("\nYour encrypted message is:- ");
	for(i=0;enc_mes[i]!='\0';i++)
	{
		printf("%c",++enc_mes[i]);
	}
	return 0;
}

int decrypt()								//Data Decryption
{
	char choice4;
	int i;
	printf("\nEnter your encrypted message:- ");
	fgets(dec_mes,MAX,stdin);
	printf("\nYour decrypted message is:- ");
	for(i=0;dec_mes[i]!='\0';i++)
	{
		printf("%c",--dec_mes[i]);
	}
	printf("\n\nDo you want to store your decrypted message? (Y/N)");
	scanf("%c",&choice4);
	if(choice4=='y')
	file_operation();
	return 0;
}

int cleaner()								//Terminal Cleaning
{
	system("clear");
	return 0;
}

int whatiscrypt()							//Info
{
	printf("\nCryptography involves creating written or generated codes that allow information to be kept secret. Cryptography converts data into a format that is unreadable for an unauthorized user, allowing it to be transmitted without unauthorized entities decoding it back into a readable format, thus compromising the data.Information security uses cryptography on several levels. The information cannot be read without a key to decrypt it. The information maintains its integrity during transit and while being stored. Cryptography also aids in nonrepudiation. This means that the sender and the delivery of a message can be verified.Cryptography is also known as cryptology\n");
return 0;
}

int file_operation()
{
	FILE *fptr;
	fptr = fopen("decrypt.txt","w");
	if(fptr==NULL)
	{
		printf("\nError while file creating");
		exit(1);
	}
	fprintf(fptr,"%s",dec_mes);
	return 0;


}
