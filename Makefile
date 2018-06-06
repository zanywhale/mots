TOOLCHAIN_PATH=/opt/cross/mipseb-linux-musl
CC=$(TOOLCHAIN_PATH)/bin/mipseb-linux-musl-gcc
LDFLAGS=-L$(TOOLCHAIN_PATH)/lib -L./libpcap-1.8.1/
CFLAGS=-I./libpcap-1.8.1/

OBJECTS=mots.o dns.o
SRCS=mots.c
TARGET=mots

$(TARGET) : $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS) $(CFLAGS) $(LDFLAGS) -g -static -lpcap

clean:
	rm $(OBJECTS)
