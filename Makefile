CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -pthread
LDFLAGS = -lpthread

TARGET  = server

all: $(TARGET)

$(TARGET): server.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: all
	./$(TARGET)

.PHONY: all clean run
