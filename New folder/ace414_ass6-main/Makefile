CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
OBJFILES = monitor.o

TARGET = assign_6


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CCFLAGS) $(DBUG) -o $(TARGET) $(OBJFILES) -lpcap

clean:
	rm -f $(TARGET) *.o
