CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = encrypt_lib.o rsa.o utils.o

TARGET = encrypt_lib


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CFLAGS) $(DBG) -o $(TARGET) $(OBJFILES) -lm

clean:
	rm -f $(TARGET) *.o
