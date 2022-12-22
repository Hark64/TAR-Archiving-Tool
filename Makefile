CC = gcc

CFLAGS = -ansi -pedantic -Wall -Werror

all: mytar

mytar: mytar.o
	$(CC) $(CFLAGS) -o mytar mytar.o

mytar.o: mytar.c
	$(CC) $(CFLAGS) -c mytar.c

clean: mytar
	rm -f *.o
