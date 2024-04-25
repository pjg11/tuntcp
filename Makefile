CFLAGS+=-Wall -Werror -Wpedantic

all: ping

ping: main.c
	cc $(CFLAGS) -o ping main.c

clean:
	rm ping
