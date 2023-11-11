tuntcp: main.c tuntcp.c
	gcc -o tuntcp main.c tuntcp.c

ping: ping.c tuntcp.c
	gcc -o ping ping.c tuntcp.c

clean:
	rm tuntcp ping
