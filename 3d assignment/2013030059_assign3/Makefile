CC ?= cc
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow
TARGET = assign_3
OBJECTS = main_fixed.o rsa_fixed.o

.PHONY: all clean check
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)

check: $(TARGET)
	python3 tests.py ./$(TARGET)

clean:
	rm -f $(TARGET) $(OBJECTS)
