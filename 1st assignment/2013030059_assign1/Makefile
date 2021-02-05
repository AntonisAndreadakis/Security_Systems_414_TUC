#CC = gcc
#CFLAGS = -Wall -g

# typing 'make' will invoke the first target entry in the file 
# (in this case the default target entry)
# you can name this target entry anything, but "default" or "all"
# are the most commonly used names by convention #
HEADERS = simple_crypto.h

default: demo

demo.o: demo.c simple_crypto.c $(HEADERS)
	gcc -c demo.c simple_crypto.c

demo: demo.o
	gcc demo.o -o demo

simple_crypto.o: simple_crypto.c $(HEADERS)
	gcc -c simple_crypto.c

simple_crypto: simple_crypto.o
	gcc simple_crypto.o -o simple_crypto


# To start over from scratch, type 'make clean'.  This
# removes the executable files #

clean: 
	rm demo demo.o simple_crypto.o

