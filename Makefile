CFLAGS+=-Wall -Werror -Wpedantic

all: tuntcp

tuntcp:
	cc $(CFLAGS) -o tuntcp main.c

clean:
	rm tuntcp
