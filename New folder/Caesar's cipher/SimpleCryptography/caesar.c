/*
 * Created for Khan Academy cryptography challenge
 *
 * Usage: caesar <filename> <shift>
 * - Shift can be negative to decrypt
 * - Leave shift blank to print all 26 shifts
 * June 3, 2016
*/

#include <stdio.h>
#include <stdlib.h>

void printshift(FILE *file, int shift);

int main(int argc, char *argv[])
{
	if(argc < 2 || argc > 3)
	{
		printf("Usage: %s <filename> <shift>\n - Shift can be negative to decrypt\n - Leave shift blank to print all 26 shifts\n", argv[0]);
		return 0;
	}

	FILE *file = fopen(argv[1], "r");

	if(file == 0)
	{
		printf("Could not open file\n");
	}
	else
	{
		if(argc == 2)
		{
			for(int i = 0; i < 26; i++)
			{
				printshift(file, i);
				printf("\n");
			}
		}
		else if(argc == 3)
		{
			//Ascii to integer
			int shift = atoi(argv[2]);
			printshift(file, shift);
			printf("\n");
		}

		fclose(file);
	}

	return 0;
}

void printshift(FILE *file, int shift)
{
	int index, newchar;

	while((index = fgetc(file)) != EOF)
	{
		//Space or new line, respectively
		if(index == 32 || index == 10)
		{
			printf("%c", index);
			continue;
		}

		//Capital letters
		if(index < 97)
		{
			newchar = ((index - 65) + shift) % 26;
			newchar += 65;
		}
		else
		{
			newchar = ((index - 97) + shift) % 26;
			newchar += 97;
		}

		printf("%c", newchar);
	}

	//Set the position indicator of the file stream to the beginning
	fseek(file, 0, SEEK_SET);
}


