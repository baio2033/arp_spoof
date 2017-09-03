all: spoofing

spoofing: spoofing.h arp_spoof.c
	gcc -o arp_spoof arp_spoof.c -lpcap -lpthread

clean:
	rm spoofing
