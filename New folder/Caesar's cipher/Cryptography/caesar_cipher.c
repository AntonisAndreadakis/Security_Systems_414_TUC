#include <stdio.h>
#include <stdlib.h>

void encrypt(unsigned char word[21], int shift_number){
  int i;
  for (i = 0; word[i] != '\0'; i++) {
    if(word[i] >= 'A' && word[i] <= 'Z')
      word[i] = ((word[i] - 'A' + shift_number) % 26 ) + 'A';
    if(word[i] >= 'a' && word[i] <= 'z')
      word[i] = ((word[i] - 'a' + shift_number) % 26 ) + 'a';
  }
  printf("%s\n", word);
}

void decrypt(unsigned char word[21], int shift_number){
  int i;
  for (i = 0; word[i] != '\0'; i++) {
    if(word[i] >= 'A' && word[i] <= 'Z'){
      int pos = word[i] - 'A' + shift_number;
      if(pos < 0)
        word[i] = ((pos % 26 ) + 26) + 'A';
      else
        word[i] = (pos % 26 ) + 'A';
    }
    if(word[i] >= 'a' && word[i] <= 'z'){
      int pos = word[i] - 'a' + shift_number;
      if(pos < 0)
        word[i] = ((pos % 26 ) + 26) + 'a';
      else
        word[i] = (pos % 26 ) + 'a';
    }
  }
  printf("%s\n", word);
}

int main(int argc, char *argv[])
{
  unsigned char word[21];
  int shift_number;

  scanf("%s", word);
  scanf("%d", &shift_number);

  if(shift_number > 0)
    encrypt(word, shift_number);
  else
    decrypt(word, shift_number);

  return 0;
}
