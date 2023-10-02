tcpip: main.c tcpip.c
	gcc -o tcpip main.c tcpip.c

ping: ping.c tcpip.c
	gcc -o ping ping.c tcpip.c

clean:
	rm tcpip ping
