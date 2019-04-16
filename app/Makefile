cc := gcc

all: nmagent arputils

nmagent: main.o
	cc -o nmagent main.o

main.o: main.c
	cc -c main.c

arputils: arputils.o
	cc -o arputils arputils.o -lpthread

arptuils.o: arputils.c
	cc -c arputils.c -lpthread

.PHONY : clean
clean:
	-rm *.o
	-rm nmagent
	-rm arputils
