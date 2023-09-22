tcpip: main.c
	gcc -o tcpip main.c tcpip.c

ping: ping.c
	gcc -o ping ping.c tcpip.c

clean:
	rm tcpip
