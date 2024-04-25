CFLAGS+=-Wall -Werror -Wpedantic

all: tuntcp

tuntcp: main.c tuntcp.o

ping: ping.o tuntcp.o

clean:
	rm -f tuntcp ping *.o
