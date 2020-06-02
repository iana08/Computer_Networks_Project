CC=gcc
CFLAGS=-Wall

all: compdetect compdetect_client

compdetect_client: compdetect_client.c
	$(CC) $(CFLAGS) compdetect_client.c -o compdetect_client

compdetect:compdetect.c
	$(CC) $(CFLAGS) compdetect.c -o compdetect

clean:
	rm compdetect_client compdetect
