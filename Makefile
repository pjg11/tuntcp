CFLAGS+=-Wall -Werror -Wpedantic

all: tuntcp

tuntcp: main.c tuntcp.o

ping: ping.o tuntcp.o

curl: curl.o tuntcp.o

.PHONY: clean
clean:
	rm -f tuntcp ping curl *.o
