#include<stdio.h>
#include<string.h>
#include<ctype.h>
main()
{
 //All the text which ever entered is converted to upper and without spaces
 int i,j,len1,len2,numstr[100],numkey[100],numcipher[100];
 char str[100],key[100],cipher[100];
 printf("Enter a string text to encrypt\n");
 gets(str);
 for(i=0,j=0;i<strlen(str);i++)
 {
  if(str[i]!=' ')
  {
   str[j]=toupper(str[i]);   
   j++;
  }
 }
 str[j]='\0';
 //obtaining numerical plain text ex A-0,B-1,C-2
    for(i=0;i<strlen(str);i++)
    {
     numstr[i]=str[i]-'A';    
    }   
    printf("Enter key string of random text\n");
    gets(key);
 for(i=0,j=0;i<strlen(key);i++)
 {
  if(key[i]!=' ')
  {
   key[j]=toupper(key[i]);   
   j++;
  }
 }
 key[j]='\0';
 //obtaining numerical one time pad(OTP) or key
    for(i=0;i<strlen(key);i++)
    {
     numkey[i]=key[i]-'A';    
    }  
    
    for(i=0;i<strlen(str);i++)
    {
     numcipher[i]=numstr[i]+numkey[i];
    }
    //To loop the number within 25 i.e if addition of numstr and numkey is 27 then numcipher should be 1
    for(i=0;i<strlen(str);i++)
    {
     if(numcipher[i]>25)
     {
      numcipher[i]=numcipher[i]-26;
     }
    }
    printf("One Time Pad Cipher text is\n");
    for(i=0;i<strlen(str);i++)
    {
      printf("%c",(numcipher[i]+'A')); 
    }
    printf("\n");

}
