#include<stdio.h>  
     #include<conio.h>  
     #include<stdlib.h>  
     #include<time.h>  
     #include<string.h>  
     char s[30],cp[30];  
     void main()  
     {  
          char c[26],k[30];  
          int i,index,max=26;  
          clrscr();  
          for(i=97;i<=122;i++)  
          {  
               c[i-97]=i;  
          }  
          printf("Enter plain text: ");  
          gets(s);  
          printf("Your key is: ");  
          randomize();  
          for(i=0;i<strlen(s);i++)  
          {  
               index=random(max)%26;  
               k[i]=c[index];  
          }  
          k[i]='\0';  
          puts(k);  
          getch();  
      }  