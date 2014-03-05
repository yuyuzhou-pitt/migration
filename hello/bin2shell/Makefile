CC=gcc
CFLAGS=-Wall

all: bin2shell

bin2shell:
	$(CC) $(CFLAGS) -o bin2shell bin2shell.c

install:
	cp bin2shell /usr/bin
	cp nasm2shell /usr/bin
	cp as2shell /usr/bin
clean:
	rm -rf bin2shell
