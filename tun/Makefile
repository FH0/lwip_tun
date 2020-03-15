CC = gcc
CFLAGS += -I../include -I../custom -O3 -Wall -g -ggdb
LWIP_SRC = $(wildcard ../core/*.c ../core/ipv4/*.c ../core/ipv6/*.c)
LWIP_OBJ = $(patsubst %.c,%.o,$(LWIP_SRC)) ../custom/sys_arch.o

all: liblwip.a test

liblwip.a: $(LWIP_OBJ)
	ar -r -s liblwip.a $(LWIP_OBJ)

.PHONY: clean test
clean:
	-rm -f $(LWIP_OBJ) liblwip.a test

test: liblwip.a
	$(CC) $(CFLAGS) -o test tun.c liblwip.a -lpthread
