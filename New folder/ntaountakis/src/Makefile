CC = gcc
DBG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = main.c rsa.c utils.c

TARGET = assign_3


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CCFLAGS) $(DBG) -o $(TARGET) $(OBJFILES) -lm

clean:
	rm -f $(TARGET) *.o
