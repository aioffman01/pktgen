CC = gcc
CFLAGS = -Wall -Wextra -O3 -g -pthread
TARGET = pktgen
SRCS = pktgen.c

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS)

clean:
	rm -f $(TARGET)
